/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2024 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

 package io.questdb.cutlass.line.tcp;

 import io.questdb.cutlass.line.LineMetrics;
 import io.questdb.Metrics;
 import io.questdb.cairo.CairoException;
 import io.questdb.cairo.CommitFailedException;
 import io.questdb.cairo.SecurityContext;
 import io.questdb.cairo.security.DenyAllSecurityContext;
 import io.questdb.cairo.security.SecurityContextFactory;
 import io.questdb.cutlass.auth.AuthenticatorException;
 import io.questdb.cutlass.auth.SocketAuthenticator;
 import io.questdb.cutlass.line.tcp.LineTcpParser.ParseResult;
 import io.questdb.log.Log;
 import io.questdb.log.LogFactory;
 import io.questdb.log.LogRecord;
 import io.questdb.network.IOContext;
 import io.questdb.network.IODispatcher;
 import io.questdb.network.NetworkFacade;
 import io.questdb.std.*;
 import io.questdb.std.datetime.millitime.MillisecondClock;
 import io.questdb.std.str.DirectUtf8Sequence;
 import io.questdb.std.str.DirectUtf8String;
 import io.questdb.std.str.Utf8String;
 import org.jetbrains.annotations.NotNull;
 
 public class LineTcpConnectionContext extends IOContext<LineTcpConnectionContext> {
     private static final Log LOG = LogFactory.getLog(LineTcpConnectionContext.class);
     private static final long QUEUE_FULL_LOG_HYSTERESIS_IN_MS = 10_000;
     protected final NetworkFacade nf;
     private final SocketAuthenticator authenticator;
     private final DirectUtf8String byteCharSequence = new DirectUtf8String();
     private final long checkIdleInterval;
     private final long commitInterval;
     private final LineTcpReceiverConfiguration configuration;
     private final boolean disconnectOnError;
     private final long idleTimeout;
     private final Metrics metrics;
     private final MillisecondClock milliClock;
     private final LineTcpParser parser;
     private final LineTcpMeasurementScheduler scheduler;
     private final Utf8StringObjHashMap<TableUpdateDetails> tableUpdateDetailsUtf8 = new Utf8StringObjHashMap<>();
     protected boolean peerDisconnected;
     protected long recvBufEnd;
     protected long recvBufPos;
     protected long recvBufStart;
     protected long recvBufStartOfMeasurement;
     protected SecurityContext securityContext = DenyAllSecurityContext.INSTANCE;
     private boolean goodMeasurement;
     private long lastQueueFullLogMillis = 0;
     private long nextCheckIdleTime;
     private long nextCommitTime;
     private final LineMetrics lineMetrics;
 
     public LineTcpConnectionContext(LineTcpReceiverConfiguration configuration, LineTcpMeasurementScheduler scheduler, Metrics metrics, LineMetrics lineMetrics) {
         super(
                 configuration.getFactoryProvider().getLineSocketFactory(),
                 configuration.getNetworkFacade(),
                 LOG,
                 metrics.line().connectionCountGauge()
         );
         this.lineMetrics = lineMetrics;
         try {
             this.authenticator = configuration.getSocketAuthenticator();
             this.checkIdleInterval = configuration.getMaintenanceInterval();
             this.commitInterval = configuration.getCommitInterval();
             this.configuration = configuration;
             this.disconnectOnError = configuration.getDisconnectOnError();
             this.idleTimeout = configuration.getIdleTimeout();
             this.metrics = metrics;
             this.milliClock = configuration.getMillisecondClock();
             this.parser = new LineTcpParser(configuration);
             this.scheduler = scheduler;
         } catch (Throwable t) {
             close();
             throw t;
         }
     }
 
     @Override
     public void clear() {
         super.clear();
         securityContext = DenyAllSecurityContext.INSTANCE;
         authenticator.clear();
         recvBufStart = recvBufEnd = recvBufPos = Unsafe.free(recvBufStart, recvBufEnd - recvBufStart, MemoryTag.NATIVE_ILP_RSS);
         peerDisconnected = false;
         resetParser();
         ObjList<Utf8String> keys = tableUpdateDetailsUtf8.keys();
         for (int n = keys.size() - 1; n >= 0; --n) {
             TableUpdateDetails tud = tableUpdateDetailsUtf8.get(keys.getQuick(n));
             if (tud != null) {
                 tud.release();
             }
         }
         tableUpdateDetailsUtf8.clear();
     }
 
     @Override
     public void close() {
         clear();
         Misc.free(authenticator);
     }
 
     public long commitWalTables(long wallClockMillis) {
         long minTableNextCommitTime = Long.MAX_VALUE;
         for (int n = 0, sz = tableUpdateDetailsUtf8.size(); n < sz; n++) {
             TableUpdateDetails tud = tableUpdateDetailsUtf8.get(tableUpdateDetailsUtf8.keys().getQuick(n));
             if (tud != null) {
                 try {
                     long nextCommitTime = tud.commitWalTable(wallClockMillis);
                     if (nextCommitTime < minTableNextCommitTime) {
                         minTableNextCommitTime = nextCommitTime;
                     }
                 } catch (CommitFailedException e) {
                     LOG.error().$("could not commit WAL table [table=").$(tud.getTableNameUtf8()).$(", error=").$(e.getFlyweightMessage()).$(']').$();
                 }
             }
         }
         // if no tables, just use the default commit interval
         return minTableNextCommitTime != Long.MAX_VALUE ? minTableNextCommitTime : wallClockMillis + commitInterval;
     }
 
     public void doMaintenance(long now) {
         if (now > nextCommitTime) {
             nextCommitTime = commitWalTables(now);
         }
 
         if (now > nextCheckIdleTime) {
             nextCheckIdleTime = now + checkIdleInterval;
             if (recvBufPos == recvBufStart) {
                 if (now - getLastNetworkActivityTime() > idleTimeout) {
                     LOG.info().$("idle timeout [fd=").$(getFd()).$(']').$();
                     throw CairoException.nonCritical().put("idle timeout");
                 }
             }
         }
     }
 
     public TableUpdateDetails getTableUpdateDetails(DirectUtf8Sequence tableName) {
         return tableUpdateDetailsUtf8.get(tableName);
     }
 
     public IOContextResult handleIO(NetworkIOJob netIoJob) {
         if (authenticator.isAuthenticated()) {
             return parseMeasurements(netIoJob);
         } else {
             return handleAuthentication(netIoJob);
         }
     }
 
     @Override
     public void init() {
         if (socket.supportsTls()) {
             if (socket.startTlsSession(null) != 0) {
                 throw CairoException.nonCritical().put("failed to start TLS session");
             }
         }
     }
 
     @Override
     public LineTcpConnectionContext of(long fd, @NotNull IODispatcher<LineTcpConnectionContext> dispatcher) {
         super.of(fd, dispatcher);
         if (recvBufStart == 0) {
             recvBufStart = Unsafe.malloc(configuration.getNetMsgBufferSize(), MemoryTag.NATIVE_ILP_RSS);
             recvBufEnd = recvBufStart + configuration.getNetMsgBufferSize();
             recvBufPos = recvBufStart;
             resetParser();
         }
         authenticator.init(socket, recvBufStart, recvBufEnd, 0, 0);
         if (authenticator.isAuthenticated() && securityContext == DenyAllSecurityContext.INSTANCE) {
             // when security context has not been set by anything else (subclass) we assume
             // this is an authenticated, anonymous user
             securityContext = configuration.getFactoryProvider().getSecurityContextFactory().getInstance(
                     null,
                     SecurityContext.AUTH_TYPE_NONE,
                     SecurityContextFactory.ILP
             );
             securityContext.authorizeLineTcp();
         }
         return this;
     }
 
     private boolean checkQueueFullLogHysteresis() {
         long millis = milliClock.getTicks();
         if ((millis - lastQueueFullLogMillis) >= QUEUE_FULL_LOG_HYSTERESIS_IN_MS) {
             lastQueueFullLogMillis = millis;
             return true;
         }
         return false;
     }
 
     private void doHandleDisconnectEvent() {
         if (parser.getBufferAddress() == recvBufEnd) {
             LOG.error().$('[').$(getFd()).$("] buffer overflow [line.tcp.msg.buffer.size=").$(recvBufEnd - recvBufStart).$(']').$();
             return;
         }
 
         if (peerDisconnected) {
             // Peer disconnected, we have now finished disconnect our end
             if (recvBufPos != recvBufStart) {
                 LOG.info().$('[').$(getFd()).$("] peer disconnected with partial measurement, ").$(recvBufPos - recvBufStart)
                         .$(" unprocessed bytes").$();
             } else {
                 LOG.info().$('[').$(getFd()).$("] peer disconnected").$();
             }
         }
     }
 
     private IOContextResult handleAuthentication(NetworkIOJob netIoJob) {
         try {
             authenticator.authenticate(netIoJob);
             if (authenticator.isAuthenticated()) {
                 securityContext = configuration.getFactoryProvider().getSecurityContextFactory().getInstance(
                         authenticator.getPrincipal(),
                         authenticator.getAuthType(),
                         SecurityContextFactory.ILP
                 );
                 securityContext.authorizeLineTcp();
                 return parseMeasurements(netIoJob);
             }
             return IOContextResult.NEEDS_READ;
         } catch (AuthenticatorException e) {
             LOG.error().$('[').$(getFd()).$("] authentication failed [error=").$(e.getFlyweightMessage()).$(']').$();
             return IOContextResult.NEEDS_DISCONNECT;
         }
     }
 
     private void logParseError() {
         int position = (int) (parser.getBufferAddress() - recvBufStartOfMeasurement);
         assert position >= 0;
         LOG.error()
                 .$('[').$(getFd())
                 .$("] could not parse measurement, ").$(parser.getErrorCode())
                 .$(" at ").$(position)
                 .$(", line (may be mangled due to partial parsing): '")
                 .$(byteCharSequence.of(recvBufStartOfMeasurement, parser.getBufferAddress(), false)).$("'")
                 .$();
     }
 
     private void startNewMeasurement() {
         parser.startNextMeasurement();
         recvBufStartOfMeasurement = parser.getBufferAddress();
         // we ran out of buffer, move to start and start parsing new data from socket
         if (recvBufStartOfMeasurement == recvBufPos) {
             recvBufPos = recvBufStart;
         }
     }
 
     void addTableUpdateDetails(Utf8String tableNameUtf8, TableUpdateDetails tableUpdateDetails) {
         tableUpdateDetailsUtf8.put(tableNameUtf8, tableUpdateDetails);
     }
 
     protected final boolean compactBuffer(long recvBufStartOfMeasurement) {
         if (recvBufStartOfMeasurement > recvBufStart) {
             long len = recvBufPos - recvBufStartOfMeasurement;
             if (len > 0) {
                 Unsafe.getUnsafe().copyMemory(recvBufStartOfMeasurement, recvBufStart, len);
             }
             recvBufPos = recvBufStart + len;
             return true;
         }
         return false;
     }
 
     protected SecurityContext getSecurityContext() {
         return securityContext;
     }
 
     protected final IOContextResult parseMeasurements(NetworkIOJob netIoJob) {
         while (recvBufPos < recvBufEnd) {
             long bytesRead = nf.recv(fd, recvBufPos, recvBufEnd - recvBufPos);
             if (bytesRead > 0) {
                 recvBufPos += bytesRead;
                 lineMetrics.lineTcpRecvBytes().add(bytesRead);
                 while (parser.parseMeasurement(recvBufStart, recvBufPos)) {
                     if (parser.isGoodMeasurement()) {
                         goodMeasurement = true;
                         scheduler.scheduleEvent(parser.getTableNameUtf8(), parser.getMeasurement());
                         startNewMeasurement();
                     } else {
                         logParseError();
                         if (disconnectOnError) {
                             return IOContextResult.NEEDS_DISCONNECT;
                         }
                         startNewMeasurement();
                     }
                 }
             } else if (bytesRead == 0) {
                 return IOContextResult.NEEDS_READ;
             } else {
                 if (bytesRead == -1) {
                     peerDisconnected = true;
                     doHandleDisconnectEvent();
                     return IOContextResult.NEEDS_DISCONNECT;
                 }
                 return IOContextResult.NEEDS_DISCONNECT;
             }
         }
         return IOContextResult.NEEDS_READ;
     }
 
     protected boolean read() {
         long bytesRead = nf.recv(fd, recvBufPos, recvBufEnd - recvBufPos);
         if (bytesRead > 0) {
             recvBufPos += bytesRead;
             lineMetrics.lineTcpRecvBytes().add(bytesRead);
             return true;
         }
         return false;
     }
 
     TableUpdateDetails removeTableUpdateDetails(DirectUtf8Sequence tableNameUtf8) {
         return tableUpdateDetailsUtf8.remove(tableNameUtf8);
     }
 
     protected void resetParser() {
         parser.of(recvBufStart, recvBufEnd);
     }
 
     protected void resetParser(long pos) {
         parser.of(pos, recvBufEnd);
     }
 
     public enum IOContextResult {
         NEEDS_READ, NEEDS_WRITE, QUEUE_FULL, NEEDS_DISCONNECT
     }
 }
