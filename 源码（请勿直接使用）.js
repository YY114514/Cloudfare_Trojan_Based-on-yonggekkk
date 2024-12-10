// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from "cloudflare:sockets";

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = "86c50e3a-5b87-49dd-bd20-03c7f2735e40";

const proxyIPs = ["47.251.95.178"]; //34.81.35.248 ts.hpc.tw edgetunnel.anycast.eu.org bestproxy.onecf.eu.org cdn-all.xn--b6gac.eu.org cdn.xn--b6gac.eu.org proxy.xxxxxxxx.tk
const cn_hostnames = [''];
let CDNIP = 'www.visa.com.sg'
// http_ip
let IP1 = 'www.visa.com'
let IP2 = 'cis.visa.com'
let IP3 = 'africa.visa.com'
let IP4 = 'www.visa.com.sg'
let IP5 = 'www.visaeurope.at'
let IP6 = 'www.visa.com.mt'
let IP7 = 'qa.visamiddleeast.com'

// https_ip
let IP8 = 'usa.visa.com'
let IP9 = 'myanmar.visa.com'
let IP10 = 'www.visa.com.tw'
let IP11 = 'www.visaeurope.ch'
let IP12 = 'www.visa.com.br'
let IP13 = 'www.visasoutheasteurope.com'

// http_port
let PT1 = '80'
let PT2 = '8080'
let PT3 = '8880'
let PT4 = '2052'
let PT5 = '2082'
let PT6 = '2086'
let PT7 = '2095'

// https_port
let PT8 = '443'
let PT9 = '8443'
let PT10 = '2053'
let PT11 = '2083'
let PT12 = '2087'
let PT13 = '2096'

let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let proxyPort = proxyIP.includes(':') ? proxyIP.split(':')[1] : '443';

if (!isValidUUID(userID)) {
  throw new Error("uuid is not valid");
}

export default {
  /**
   * @param {import("@cloudflare/workers-types").Request} request
   * @param {uuid: string, proxyip: string, cdnip: string, ip1: string, ip2: string, ip3: string, ip4: string, ip5: string, ip6: string, ip7: string, ip8: string, ip9: string, ip10: string, ip11: string, ip12: string, ip13: string, pt1: string, pt2: string, pt3: string, pt4: string, pt5: string, pt6: string, pt7: string, pt8: string, pt9: string, pt10: string, pt11: string, pt12: string, pt13: string} env
   * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      const { proxyip } = env;
      userID = env.uuid || userID;
			if (proxyip) {
				if (proxyip.includes(']:')) {
					let lastColonIndex = proxyip.lastIndexOf(':');
					proxyPort = proxyip.slice(lastColonIndex + 1);
					proxyIP = proxyip.slice(0, lastColonIndex);
					
				} else if (!proxyip.includes(']:') && !proxyip.includes(']')) {
					[proxyIP, proxyPort = '443'] = proxyip.split(':');
				} else {
					proxyPort = '443';
					proxyIP = proxyip;
				}				
			} else {
				if (proxyIP.includes(']:')) {
					let lastColonIndex = proxyIP.lastIndexOf(':');
					proxyPort = proxyIP.slice(lastColonIndex + 1);
					proxyIP = proxyIP.slice(0, lastColonIndex);	
				} else if (!proxyIP.includes(']:') && !proxyIP.includes(']')) {
					[proxyIP, proxyPort = '443'] = proxyIP.split(':');
				} else {
					proxyPort = '443';
				}	
			}
			console.log('ProxyIP:', proxyIP);
			console.log('ProxyPort:', proxyPort);
      CDNIP = env.cdnip || CDNIP;
	  IP1 = env.ip1 || IP1;
	  IP2 = env.ip2 || IP2;
	  IP3 = env.ip3 || IP3;
	  IP4 = env.ip4 || IP4;
	  IP5 = env.ip5 || IP5;
	  IP6 = env.ip6 || IP6;
	  IP7 = env.ip7 || IP7;
	  IP8 = env.ip8 || IP8;
	  IP9 = env.ip9 || IP9;
	  IP10 = env.ip10 || IP10;
	  IP11 = env.ip11 || IP11;
	  IP12 = env.ip12 || IP12;
	  IP13 = env.ip13 || IP13;
	  PT1 = env.pt1 || PT1;
	  PT2 = env.pt2 || PT2;
	  PT3 = env.pt3 || PT3;
	  PT4 = env.pt4 || PT4;
	  PT5 = env.pt5 || PT5;
	  PT6 = env.pt6 || PT6;
	  PT7 = env.pt7 || PT7;
	  PT8 = env.pt8 || PT8;
	  PT9 = env.pt9 || PT9;
	  PT10 = env.pt10 || PT10;
	  PT11 = env.pt11 || PT11;
	  PT12 = env.pt12 || PT12;
	  PT13 = env.pt13 || PT13;
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const url = new URL(request.url);
        switch (url.pathname) {
          case `/${userID}`: {
            const vlessConfig = getVLESSConfig(userID, request.headers.get("Host"));
            return new Response(`${vlessConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/html;charset=utf-8",
              },
            });
          }
		  case `/${userID}/ty`: {
			const tyConfig = gettyConfig(userID, request.headers.get('Host'));
			return new Response(`${tyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/cl`: {
			const clConfig = getclConfig(userID, request.headers.get('Host'));
			return new Response(`${clConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/sb`: {
			const sbConfig = getsbConfig(userID, request.headers.get('Host'));
			return new Response(`${sbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
		case `/${userID}/pty`: {
			const ptyConfig = getptyConfig(userID, request.headers.get('Host'));
			return new Response(`${ptyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/pcl`: {
			const pclConfig = getpclConfig(userID, request.headers.get('Host'));
			return new Response(`${pclConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/psb`: {
			const psbConfig = getpsbConfig(userID, request.headers.get('Host'));
			return new Response(`${psbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
          default:
            // return new Response('Not found', { status: 404 });
            // For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
            if (cn_hostnames.includes('')) {
            return new Response(JSON.stringify(request.cf, null, 4), {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              },
            });
            }
            const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
            const newHeaders = new Headers(request.headers);
            newHeaders.set("cf-connecting-ip", "1.2.3.4");
            newHeaders.set("x-forwarded-for", "1.2.3.4");
            newHeaders.set("x-real-ip", "1.2.3.4");
            newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
            // Use fetch to proxy the request to 15 different domains
            const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual",
            });
            const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
            // Check for 302 or 301 redirect status and return an error response
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                status: 403,
                statusText: "Forbidden",
              });
            }
            // Return the response from the proxy server
            return proxyResponse;
        }
      } else {
			if(url.pathname.includes('/pyip='))
			{
				const tmp_ip=url.pathname.split("=")[1];
				if(isValidIP(tmp_ip))
				{
					proxyIP=tmp_ip;
					if (proxyIP.includes(']:')) {
						let lastColonIndex = proxyIP.lastIndexOf(':');
						proxyPort = proxyIP.slice(lastColonIndex + 1);
						proxyIP = proxyIP.slice(0, lastColonIndex);	
					} else if (!proxyIP.includes(']:') && !proxyIP.includes(']')) {
						[proxyIP, proxyPort = '443'] = proxyIP.split(':');
					} else {
						proxyPort = '443';
					}
				}	
			}
        return await vlessOverWSHandler(request);
		}
    } catch (err) {
      /** @type {Error} */ let e = err;
      return new Response(e.toString());
    }
  },
};

function isValidIP(ip) {
    var reg = /^[\s\S]*$/;
    return reg.test(ip);
}

/**
 *
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function vlessOverWSHandler(request) {
  /** @type {import("@cloudflare/workers-types").WebSocket[]} */
  // @ts-ignore
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";
  const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
  let remoteSocketWapper = {
    value: null,
  };
  let udpStreamWrite = null;
  let isDns = false;

  // ws --> remote
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = await processVlessHeader(chunk, userID);
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
          if (hasError) {
            // controller.error(message);
            throw new Error(message); // cf seems has bug, controller.error will not end stream
            // webSocket.close(1000, message);
            return;
          }
          // if UDP but port not DNS port, close it
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              // controller.error('UDP proxy only enable for DNS which is port 53');
              throw new Error("UDP proxy only enable for DNS which is port 53"); // cf seems has bug, controller.error will not end stream
              return;
            }
          }
          // ["version", "附加信息长度 N"]
          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          // TODO: support udp here when cf runtime has udp support
          if (isDns) {
            const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          handleTCPOutBound(
            remoteSocketWapper,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    // @ts-ignore
    webSocket: client,
  });
}

/**
 * Checks if a given UUID is present in the API response.
 * @param {string} targetUuid The UUID to search for.
 * @returns {Promise<boolean>} A Promise that resolves to true if the UUID is present in the API response, false otherwise.
 */
async function checkUuidInApiResponse(targetUuid) {
  // Check if any of the environment variables are empty

  try {
    const apiResponse = await getApiResponse();
    if (!apiResponse) {
      return false;
    }
    const isUuidInResponse = apiResponse.users.some((user) => user.uuid === targetUuid);
    return isUuidInResponse;
  } catch (error) {
    console.error("Error:", error);
    return false;
  }
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  vlessResponseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
    /** @type {import("@cloudflare/workers-types").Socket} */
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData); // first write, nomal is tls client hello
    writer.releaseLock();
    return tcpSocket;
  }

  // if the cf connect tcp socket have no incoming data, we retry to redirect ip
  async function retry() {
    const tcpSocket = await connectAndWrite(proxyIP || addressRemote, proxyPort || portRemote);
    // no matter retry success or not, close websocket
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  // when remoteSocket is ready, pass to websocket
  // remote--> ws
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 *
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader for ws 0rtt
 * @param {(info: string)=> void} log for ws 0rtt
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });

      // The event means that the client closed the client -> server stream.
      // However, the server -> client stream is still open until you call close() on the server side.
      // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
      webSocketServer.addEventListener("close", () => {
        // client send close, need close server
        // if stream is cancel, skip controller.close
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      // for ws 0rtt
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {
      // if ws can stop read if stream is full, we can implement backpressure
      // https://streams.spec.whatwg.org/#example-rs-push-backpressure
    },
    cancel(reason) {
      // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
      // 2. if readableStream is cancel, all controller.close/enqueue need skip,
      // 3. but from testing controller.error still work even if readableStream is cancel
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 *
 * @param { ArrayBuffer} vlessBuffer
 * @param {string} userID
 * @returns
 */
async function processVlessHeader(vlessBuffer, userID) {
  if (vlessBuffer.byteLength < 24) {
    return {
      hasError: true,
      message: "invalid data",
    };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  const uuids = userID.includes(",") ? userID.split(",") : [userID];

  const checkUuidInApi = await checkUuidInApiResponse(slicedBufferString);
  isValidUser = uuids.some((userUuid) => checkUuidInApi || slicedBufferString === userUuid.trim());

  console.log(`checkUuidInApi: ${await checkUuidInApiResponse(slicedBufferString)}, userID: ${slicedBufferString}`);

  if (!isValidUser) {
    return {
      hasError: true,
      message: "invalid user",
    };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  //skip opt for now

  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  // 0x01 TCP
  // 0x02 UDP
  // 0x03 MUX
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  // port is big-Endian in raw data etc 80 == 0x005d
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

  // 1--> ipv4  addressLength =4
  // 2--> domain name addressLength=addressBuffer[1]
  // 3--> ipv6  addressLength =16
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      // seems no need add [] for ipv6
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

/**
 *
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket
 * @param {ArrayBuffer} vlessResponseHeader
 * @param {(() => Promise<void>) | null} retry
 * @param {*} log
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
  // remote--> ws
  let remoteChunkCount = 0;
  let chunks = [];
  /** @type {ArrayBuffer | null} */
  let vlessHeader = vlessResponseHeader;
  let hasIncomingData = false; // check if remoteSocket has incoming data
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        /**
         *
         * @param {Uint8Array} chunk
         * @param {*} controller
         */
        async write(chunk, controller) {
          hasIncomingData = true;
          // remoteChunkCount++;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (vlessHeader) {
            webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
            vlessHeader = null;
          } else {
            // seems no need rate limit this, CF seems fix this??..
            // if (remoteChunkCount > 20000) {
            // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
            // 	await delay(1);
            // }
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
          // safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });

  // seems is cf connect socket have error,
  // 1. Socket.closed will have error
  // 2. Socket.readable will be close without any data coming
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

/**
 *
 * @param {string} base64Str
 * @returns
 */
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    // go use modified Base64 for URL rfc4648 which js atob not support
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

/**
 * This is not real UUID validation
 * @param {string} uuid
 */
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Normally, WebSocket will not has exceptions when close.
 * @param {import("@cloudflare/workers-types").WebSocket} socket
 */
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
 
/**
 *
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket
 * @param {ArrayBuffer} vlessResponseHeader
 * @param {(string)=> void} log
 */
async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      // udp message 2 byte is the the length of udp data
      // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });

  // only handle dns udp for now
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch(
            dohURL, // dns server url
            {
              method: "POST",
              headers: {
                "content-type": "application/dns-message",
              },
              body: chunk,
            }
          );
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            log(`doh success and dns message length is ${udpSize}`);
            if (isVlessHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isVlessHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      log("dns udp has error" + error);
    });

  const writer = transformStream.writable.getWriter();

  return {
    /**
     *
     * @param {Uint8Array} chunk
     */
    write(chunk) {
      writer.write(chunk);
    },
  };
}

/**
 *
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */
function getVLESSConfig(userID, hostName) {
  const wvlessws = `vless\u003A//${userID}\u0040${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
  const pvlesswstls = `vless\u003A//${userID}\u0040${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;
  const note = `甬哥博客地址：https://ygkkk.blogspot.com\n甬哥YouTube频道：https://www.youtube.com/@ygkkk\n甬哥TG电报群组：https://t.me/ygkkktg\n甬哥TG电报频道：https://t.me/ygkkktgpd\n\nProxyIP全局运行中：${proxyIP}`;
  const ty = `https://${hostName}/${userID}/ty`
  const cl = `https://${hostName}/${userID}/cl`
  const sb = `https://${hostName}/${userID}/sb`
  const pty = `https://${hostName}/${userID}/pty`
  const pcl = `https://${hostName}/${userID}/pcl`
  const psb = `https://${hostName}/${userID}/psb`
  const noteshow = note.replace(/\n/g, '<br>');
  const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<style>
.limited-width {
    max-width: 200px;
    overflow: auto;
    word-wrap: break-word;
}
</style>
</head>
<script>
function copyToClipboard(text) {
  const input = document.createElement('textarea');
  input.style.position = 'fixed';
  input.style.opacity = 0;
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('Copy');
  document.body.removeChild(input);
  alert('已复制到剪贴板');
}
</script>
`;
if (hostName.includes("workers.dev")) {
return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare-workers/pages-vless代理脚本 V24.10.18</h1>
	    <hr>
            <p>${noteshow}</p>
            <hr>
	    <hr>
	    <hr>
            <br>
            <br>
            <h3>1：CF-workers-vless+ws节点</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">关闭了TLS加密，无视域名阻断</td>
						<td class="limited-width">${wvlessws}</td>
						<td><button class="btn btn-primary" onclick="copyToClipboard('${wvlessws}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：7个http端口可任意选择(80、8080、8880、2052、2082、2086、2095)，或反代IP对应端口</li>
                <li>用户ID(uuid)：${userID}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
		<li>传输安全(TLS)：关闭</li>
            </ul>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
            <h3>2：CF-workers-vless+ws+tls节点</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">启用了TLS加密，<br>如果客户端支持分片(Fragment)功能，建议开启，防止域名阻断</td>
						<td class="limited-width">${pvlesswstls}</td>	
						<td><button class="btn btn-primary" onclick="copyToClipboard('${pvlesswstls}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                <li>用户ID(uuid)：${userID}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
                <li>传输安全(TLS)：开启</li>
                <li>跳过证书验证(allowlnsecure)：false</li>
			</ul>
			<hr>
			<hr>
			<hr>
			<br>	
			<br>
			<h3>3：聚合通用、Clash-meta、Sing-box订阅链接如下：</h3>
			<hr>
			<p>注意：<br>1、默认每个订阅链接包含TLS+非TLS共13个端口节点<br>2、当前workers域名作为订阅链接，需通过代理进行订阅更新<br>3、如使用的客户端不支持分片功能，则TLS节点不可用</p>
			<hr>
			<table class="table">
					<thead>
						<tr>
							<th>聚合通用订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${ty}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${ty}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>	

				<table class="table">
						<thead>
							<tr>
								<th>Clash-meta订阅链接：</th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td class="limited-width">${cl}</td>	
								<td><button class="btn btn-primary" onclick="copyToClipboard('${cl}')">点击复制链接</button></td>
							</tr>
						</tbody>
					</table>

					<table class="table">
					<thead>
						<tr>
							<th>Sing-box订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${sb}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${sb}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>
				<br>
				<br>
        </div>
    </div>
</div>
</body>
`;
  } else {
    return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare-workers/pages-vless代理脚本 V24.10.18</h1>
			<hr>
            <p>${noteshow}</p>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
            <h3>1：CF-pages/workers/自定义域-vless+ws+tls节点</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">启用了TLS加密，<br>如果客户端支持分片(Fragment)功能，可开启，防止域名阻断</td>
						<td class="limited-width">${pvlesswstls}</td>
						<td><button class="btn btn-primary" onclick="copyToClipboard('${pvlesswstls}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                <li>用户ID(uuid)：${userID}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
                <li>传输安全(TLS)：开启</li>
                <li>跳过证书验证(allowlnsecure)：false</li>
			</ul>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
			<h3>2：聚合通用、Clash-meta、Sing-box订阅链接如下：</h3>
			<hr>
			<p>注意：以下订阅链接仅6个TLS端口节点</p>
			<hr>
			<table class="table">
					<thead>
						<tr>
							<th>聚合通用订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${pty}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${pty}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>	

				<table class="table">
						<thead>
							<tr>
								<th>Clash-meta订阅链接：</th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td class="limited-width">${pcl}</td>	
								<td><button class="btn btn-primary" onclick="copyToClipboard('${pcl}')">点击复制链接</button></td>
							</tr>
						</tbody>
					</table>

					<table class="table">
					<thead>
						<tr>
							<th>Sing-box订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${psb}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${psb}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>
				<br>
				<br>
        </div>
    </div>
</div>
</body>
`;
  }
}

function gettyConfig(userID, hostName) {
	const vlessshare = btoa(`vless\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\nvless\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\nvless\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\nvless\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\nvless\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\nvless\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\nvless\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\nvless\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
		return `${vlessshare}`
	}

function getclConfig(userID, hostName) {
return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V1_${IP1}_${PT1}
  type: vless
  server: ${IP1}
  port: ${PT1}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V2_${IP2}_${PT2}
  type: vless
  server: ${IP2}
  port: ${PT2}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V3_${IP3}_${PT3}
  type: vless
  server: ${IP3}
  port: ${PT3}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V4_${IP4}_${PT4}
  type: vless
  server: ${IP4}
  port: ${PT4}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V5_${IP5}_${PT5}
  type: vless
  server: ${IP5}
  port: ${PT5}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V6_${IP6}_${PT6}
  type: vless
  server: ${IP6}
  port: ${PT6}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V7_${IP7}_${PT7}
  type: vless
  server: ${IP7}
  port: ${PT7}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🛑 全球拦截
  type: select
  proxies:
    - REJECT
    - DIRECT

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 📺哔哩哔哩
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - DOMAIN-SUFFIX,acl4.ssr,选择代理
  - DOMAIN-SUFFIX,ip6-localhost,选择代理
  - DOMAIN-SUFFIX,ip6-loopback,选择代理
  - DOMAIN-SUFFIX,lan,选择代理
  - DOMAIN-SUFFIX,local,选择代理
  - DOMAIN-SUFFIX,localhost,选择代理
  - IP-CIDR,0.0.0.0/8,选择代理,no-resolve
  - IP-CIDR,10.0.0.0/8,选择代理,no-resolve
  - IP-CIDR,100.64.0.0/10,选择代理,no-resolve
  - IP-CIDR,127.0.0.0/8,选择代理,no-resolve
  - IP-CIDR,172.16.0.0/12,选择代理,no-resolve
  - IP-CIDR,192.168.0.0/16,选择代理,no-resolve
  - IP-CIDR,198.18.0.0/16,选择代理,no-resolve
  - IP-CIDR,224.0.0.0/4,选择代理,no-resolve
  - IP-CIDR6,::1/128,选择代理,no-resolve
  - IP-CIDR6,fc00::/7,选择代理,no-resolve
  - IP-CIDR6,fe80::/10,选择代理,no-resolve
  - IP-CIDR6,fd00::/8,选择代理,no-resolve
  - DOMAIN,instant.arubanetworks.com,选择代理
  - DOMAIN,setmeup.arubanetworks.com,选择代理
  - DOMAIN,router.asus.com,选择代理
  - DOMAIN,www.asusrouter.com,选择代理
  - DOMAIN-SUFFIX,hiwifi.com,选择代理
  - DOMAIN-SUFFIX,leike.cc,选择代理
  - DOMAIN-SUFFIX,miwifi.com,选择代理
  - DOMAIN-SUFFIX,my.router,选择代理
  - DOMAIN-SUFFIX,p.to,选择代理
  - DOMAIN-SUFFIX,peiluyou.com,选择代理
  - DOMAIN-SUFFIX,phicomm.me,选择代理
  - DOMAIN-SUFFIX,router.ctc,选择代理
  - DOMAIN-SUFFIX,routerlogin.com,选择代理
  - DOMAIN-SUFFIX,tendawifi.com,选择代理
  - DOMAIN-SUFFIX,zte.home,选择代理
  - DOMAIN-SUFFIX,tplogin.cn,选择代理
  - DOMAIN-SUFFIX,wifi.cmcc,选择代理
  - DOMAIN-SUFFIX,ol.epicgames.com,选择代理
  - DOMAIN-SUFFIX,dizhensubao.getui.com,选择代理
  - DOMAIN,dl.google.com,选择代理
  - DOMAIN-SUFFIX,googletraveladservices.com,选择代理
  - DOMAIN-SUFFIX,tracking-protection.cdn.mozilla.net,选择代理
  - DOMAIN,origin-a.akamaihd.net,选择代理
  - DOMAIN,fairplay.l.qq.com,选择代理
  - DOMAIN,livew.l.qq.com,选择代理
  - DOMAIN,vd.l.qq.com,选择代理
  - DOMAIN,errlog.umeng.com,选择代理
  - DOMAIN,msg.umeng.com,选择代理
  - DOMAIN,msg.umengcloud.com,选择代理
  - DOMAIN,tracking.miui.com,选择代理
  - DOMAIN,app.adjust.com,选择代理
  - DOMAIN,bdtj.tagtic.cn,选择代理
  - DOMAIN,rewards.hypixel.net,选择代理
  - DOMAIN-SUFFIX,koodomobile.com,选择代理
  - DOMAIN-SUFFIX,koodomobile.ca,选择代理
  - DOMAIN-KEYWORD,admarvel,🛑 全球拦截
  - DOMAIN-KEYWORD,admaster,🛑 全球拦截
  - DOMAIN-KEYWORD,adsage,🛑 全球拦截
  - DOMAIN-KEYWORD,adsensor,🛑 全球拦截
  - DOMAIN-KEYWORD,adsmogo,🛑 全球拦截
  - DOMAIN-KEYWORD,adsrvmedia,🛑 全球拦截
  - DOMAIN-KEYWORD,adsserving,🛑 全球拦截
  - DOMAIN-KEYWORD,adsystem,🛑 全球拦截
  - DOMAIN-KEYWORD,adwords,🛑 全球拦截
  - DOMAIN-KEYWORD,applovin,🛑 全球拦截
  - DOMAIN-KEYWORD,appsflyer,🛑 全球拦截
  - DOMAIN-KEYWORD,domob,🛑 全球拦截
  - DOMAIN-KEYWORD,duomeng,🛑 全球拦截
  - DOMAIN-KEYWORD,dwtrack,🛑 全球拦截
  - DOMAIN-KEYWORD,guanggao,🛑 全球拦截
  - DOMAIN-KEYWORD,omgmta,🛑 全球拦截
  - DOMAIN-KEYWORD,omniture,🛑 全球拦截
  - DOMAIN-KEYWORD,openx,🛑 全球拦截
  - DOMAIN-KEYWORD,partnerad,🛑 全球拦截
  - DOMAIN-KEYWORD,pingfore,🛑 全球拦截
  - DOMAIN-KEYWORD,socdm,🛑 全球拦截
  - DOMAIN-KEYWORD,supersonicads,🛑 全球拦截
  - DOMAIN-KEYWORD,wlmonitor,🛑 全球拦截
  - DOMAIN-KEYWORD,zjtoolbar,🛑 全球拦截
  - DOMAIN-SUFFIX,09mk.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,100peng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,114la.com,🛑 全球拦截
  - DOMAIN-SUFFIX,123juzi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,138lm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,17un.com,🛑 全球拦截
  - DOMAIN-SUFFIX,2cnt.net,🛑 全球拦截
  - DOMAIN-SUFFIX,3gmimo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,3xx.vip,🛑 全球拦截
  - DOMAIN-SUFFIX,51.la,🛑 全球拦截
  - DOMAIN-SUFFIX,51taifu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,51yes.com,🛑 全球拦截
  - DOMAIN-SUFFIX,600ad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,6dad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,70e.com,🛑 全球拦截
  - DOMAIN-SUFFIX,86.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,8le8le.com,🛑 全球拦截
  - DOMAIN-SUFFIX,8ox.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,95558000.com,🛑 全球拦截
  - DOMAIN-SUFFIX,99click.com,🛑 全球拦截
  - DOMAIN-SUFFIX,99youmeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a3p4.net,🛑 全球拦截
  - DOMAIN-SUFFIX,acs86.com,🛑 全球拦截
  - DOMAIN-SUFFIX,acxiom-online.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-brix.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-delivery.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-locus.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-plus.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad7.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adadapted.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adadvisor.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adap.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,adbana.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adchina.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adcome.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ader.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,adform.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adfuture.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adhouyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adinfuse.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adirects.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adjust.io,🛑 全球拦截
  - DOMAIN-SUFFIX,adkmob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adlive.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adlocus.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admaji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admin6.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admon.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adnyg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adpolestar.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adpro.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adpush.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adquan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adreal.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ads8.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsame.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsmogo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsmogo.org,🛑 全球拦截
  - DOMAIN-SUFFIX,adsunflower.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsunion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adtrk.me,🛑 全球拦截
  - DOMAIN-SUFFIX,adups.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aduu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,advertising.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adview.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,advmob.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adwetec.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adwhirl.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adwo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adxmi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adzerk.net,🛑 全球拦截
  - DOMAIN-SUFFIX,agrant.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,agrantsem.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aihaoduo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ajapk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,allyes.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,allyes.com,🛑 全球拦截
  - DOMAIN-SUFFIX,amazon-adsystem.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analysys.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,angsrvr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,anquan.org,🛑 全球拦截
  - DOMAIN-SUFFIX,anysdk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appadhoc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appboy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appdriver.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,appjiagu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,applifier.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appsflyer.com,🛑 全球拦截
  - DOMAIN-SUFFIX,atdmt.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baifendian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,banmamedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baoyatu.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,baycode.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,bayimob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,behe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bfshan.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,biddingos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,biddingx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bjvvqu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,bjxiaohua.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bloggerads.net,🛑 全球拦截
  - DOMAIN-SUFFIX,branch.io,🛑 全球拦截
  - DOMAIN-SUFFIX,bsdev.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,bshare.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,btyou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bugtags.com,🛑 全球拦截
  - DOMAIN-SUFFIX,buysellads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c0563.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cacafly.com,🛑 全球拦截
  - DOMAIN-SUFFIX,casee.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cdnmaster.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chance-ad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chanet.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,chartbeat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chartboost.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chengadx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chmae.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clickadu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clicki.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,clicktracks.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clickzs.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cloudmobi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,cmcore.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cnxad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cnzz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cnzzlink.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cocounion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,coocaatv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cooguo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,coolguang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,coremetrics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpmchina.co,🛑 全球拦截
  - DOMAIN-SUFFIX,cpx24.com,🛑 全球拦截
  - DOMAIN-SUFFIX,crasheye.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,crosschannel.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ctrmi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,customer-security.online,🛑 全球拦截
  - DOMAIN-SUFFIX,daoyoudao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,datouniao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ddapp.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dianjoy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dianru.com,🛑 全球拦截
  - DOMAIN-SUFFIX,disqusads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,domob.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,domob.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,domob.org,🛑 全球拦截
  - DOMAIN-SUFFIX,dotmore.com.tw,🛑 全球拦截
  - DOMAIN-SUFFIX,doubleverify.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doudouguo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doumob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,duanat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,duiba.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,duomeng.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dxpmedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,edigitalsurvey.com,🛑 全球拦截
  - DOMAIN-SUFFIX,eduancm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,emarbox.com,🛑 全球拦截
  - DOMAIN-SUFFIX,exosrv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fancyapi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,feitian001.com,🛑 全球拦截
  - DOMAIN-SUFFIX,feixin2.com,🛑 全球拦截
  - DOMAIN-SUFFIX,flashtalking.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fraudmetrix.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,g1.tagtic.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gentags.net,🛑 全球拦截
  - DOMAIN-SUFFIX,gepush.com,🛑 全球拦截
  - DOMAIN-SUFFIX,getui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,glispa.com,🛑 全球拦截
  - DOMAIN-SUFFIX,go-mpulse,🛑 全球拦截
  - DOMAIN-SUFFIX,go-mpulse.net,🛑 全球拦截
  - DOMAIN-SUFFIX,godloveme.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gridsum.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gridsumdissector.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gridsumdissector.com,🛑 全球拦截
  - DOMAIN-SUFFIX,growingio.com,🛑 全球拦截
  - DOMAIN-SUFFIX,guohead.com,🛑 全球拦截
  - DOMAIN-SUFFIX,guomob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,haoghost.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hivecn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hypers.com,🛑 全球拦截
  - DOMAIN-SUFFIX,icast.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,igexin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,il8r.com,🛑 全球拦截
  - DOMAIN-SUFFIX,imageter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,immob.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,inad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobi.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobicdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobicdn.net,🛑 全球拦截
  - DOMAIN-SUFFIX,innity.com,🛑 全球拦截
  - DOMAIN-SUFFIX,instabug.com,🛑 全球拦截
  - DOMAIN-SUFFIX,intely.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,iperceptions.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ipinyou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,irs01.com,🛑 全球拦截
  - DOMAIN-SUFFIX,irs01.net,🛑 全球拦截
  - DOMAIN-SUFFIX,irs09.com,🛑 全球拦截
  - DOMAIN-SUFFIX,istreamsche.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jesgoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jiaeasy.net,🛑 全球拦截
  - DOMAIN-SUFFIX,jiguang.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jimdo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jisucn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jmgehn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jpush.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jusha.com,🛑 全球拦截
  - DOMAIN-SUFFIX,juzi.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,juzilm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kejet.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kejet.net,🛑 全球拦截
  - DOMAIN-SUFFIX,keydot.net,🛑 全球拦截
  - DOMAIN-SUFFIX,keyrun.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,kmd365.com,🛑 全球拦截
  - DOMAIN-SUFFIX,krux.net,🛑 全球拦截
  - DOMAIN-SUFFIX,lnk0.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lnk8.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,localytics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lomark.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,lotuseed.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lrswl.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lufax.com,🛑 全球拦截
  - DOMAIN-SUFFIX,madhouse.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,madmini.com,🛑 全球拦截
  - DOMAIN-SUFFIX,madserving.com,🛑 全球拦截
  - DOMAIN-SUFFIX,magicwindow.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mathtag.com,🛑 全球拦截
  - DOMAIN-SUFFIX,maysunmedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mbai.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mediaplex.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mediav.com,🛑 全球拦截
  - DOMAIN-SUFFIX,megajoy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mgogo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,miaozhen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,microad-cn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,miidi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,mijifen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mixpanel.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mjmobi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mng-ads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,moad.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,moatads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobaders.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobclix.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobgi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobisage.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobvista.com,🛑 全球拦截
  - DOMAIN-SUFFIX,moogos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mopub.com,🛑 全球拦截
  - DOMAIN-SUFFIX,moquanad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mpush.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mxpnl.com,🛑 全球拦截
  - DOMAIN-SUFFIX,myhug.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mzy2014.com,🛑 全球拦截
  - DOMAIN-SUFFIX,networkbench.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ninebox.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ntalker.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nylalobghyhirgh.com,🛑 全球拦截
  - DOMAIN-SUFFIX,o2omobi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,oadz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,oneapm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,onetad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,optaim.com,🛑 全球拦截
  - DOMAIN-SUFFIX,optimix.asia,🛑 全球拦截
  - DOMAIN-SUFFIX,optimix.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,optimizelyapis.com,🛑 全球拦截
  - DOMAIN-SUFFIX,overture.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p0y.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pagechoice.net,🛑 全球拦截
  - DOMAIN-SUFFIX,pingdom.net,🛑 全球拦截
  - DOMAIN-SUFFIX,plugrush.com,🛑 全球拦截
  - DOMAIN-SUFFIX,popin.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,pro.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,publicidad.net,🛑 全球拦截
  - DOMAIN-SUFFIX,publicidad.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,pubmatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pubnub.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qcl777.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qiyou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qtmojo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,quantcount.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qucaigg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qumi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qxxys.com,🛑 全球拦截
  - DOMAIN-SUFFIX,reachmax.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,responsys.net,🛑 全球拦截
  - DOMAIN-SUFFIX,revsci.net,🛑 全球拦截
  - DOMAIN-SUFFIX,rlcdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rtbasia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sanya1.com,🛑 全球拦截
  - DOMAIN-SUFFIX,scupio.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shuiguo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shuzilm.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,similarweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sitemeter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sitescout.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sitetag.us,🛑 全球拦截
  - DOMAIN-SUFFIX,smartmad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,social-touch.com,🛑 全球拦截
  - DOMAIN-SUFFIX,somecoding.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sponsorpay.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stargame.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stg8.com,🛑 全球拦截
  - DOMAIN-SUFFIX,switchadhub.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sycbbs.com,🛑 全球拦截
  - DOMAIN-SUFFIX,synacast.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sysdig.com,🛑 全球拦截
  - DOMAIN-SUFFIX,talkingdata.com,🛑 全球拦截
  - DOMAIN-SUFFIX,talkingdata.net,🛑 全球拦截
  - DOMAIN-SUFFIX,tansuotv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tanv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tanx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tapjoy.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,th7.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,thoughtleadr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tianmidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tiqcdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,touclick.com,🛑 全球拦截
  - DOMAIN-SUFFIX,trafficjam.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,trafficmp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tuia.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ueadlian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uerzyr.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ugdtimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ugvip.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ujian.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,ukeiae.com,🛑 全球拦截
  - DOMAIN-SUFFIX,umeng.co,🛑 全球拦截
  - DOMAIN-SUFFIX,umeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,umtrack.com,🛑 全球拦截
  - DOMAIN-SUFFIX,unimhk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union-wifi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union001.com,🛑 全球拦截
  - DOMAIN-SUFFIX,unionsy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,unlitui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uri6.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ushaqi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,usingde.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uuzu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uyunad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vamaker.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vlion.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,voiceads.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,voiceads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vpon.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vungle.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,vungle.com,🛑 全球拦截
  - DOMAIN-SUFFIX,waps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wapx.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,webterren.com,🛑 全球拦截
  - DOMAIN-SUFFIX,whpxy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,winads.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,winasdaq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wiyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wooboo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wqmobile.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wrating.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wumii.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wwads.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,xcy8.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xdrig.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xiaozhen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xibao100.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xtgreat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yandui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yigao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yijifen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yinooo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yiqifa.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yiwk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ylunion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ymapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ymcdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,yongyuelm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yooli.com,🛑 全球拦截
  - DOMAIN-SUFFIX,youmi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,youxiaoad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yoyi.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,yoyi.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,yrxmr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ysjwj.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yunjiasu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yunpifu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zampdsp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zamplus.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zcdsp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zhidian3g.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zhiziyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zhjfad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zqzxz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zzsx8.com,🛑 全球拦截
  - DOMAIN-SUFFIX,acuityplatform.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-stir.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-survey.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad4game.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adcloud.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,adcolony.com,🛑 全球拦截
  - DOMAIN-SUFFIX,addthis.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adfurikun.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,adhigh.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adhood.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adinall.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adition.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adk2x.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admarket.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,admarvel.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adnxs.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adotmob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adperium.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adriver.ru,🛑 全球拦截
  - DOMAIN-SUFFIX,adroll.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsco.re,🛑 全球拦截
  - DOMAIN-SUFFIX,adservice.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsrvr.org,🛑 全球拦截
  - DOMAIN-SUFFIX,adsymptotic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adtaily.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adtech.de,🛑 全球拦截
  - DOMAIN-SUFFIX,adtechjp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adtechus.com,🛑 全球拦截
  - DOMAIN-SUFFIX,airpush.com,🛑 全球拦截
  - DOMAIN-SUFFIX,am15.net,🛑 全球拦截
  - DOMAIN-SUFFIX,amobee.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appier.net,🛑 全球拦截
  - DOMAIN-SUFFIX,applift.com,🛑 全球拦截
  - DOMAIN-SUFFIX,apsalar.com,🛑 全球拦截
  - DOMAIN-SUFFIX,atas.io,🛑 全球拦截
  - DOMAIN-SUFFIX,awempire.com,🛑 全球拦截
  - DOMAIN-SUFFIX,axonix.com,🛑 全球拦截
  - DOMAIN-SUFFIX,beintoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bepolite.eu,🛑 全球拦截
  - DOMAIN-SUFFIX,bidtheatre.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bidvertiser.com,🛑 全球拦截
  - DOMAIN-SUFFIX,blismedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,brucelead.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bttrack.com,🛑 全球拦截
  - DOMAIN-SUFFIX,casalemedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,celtra.com,🛑 全球拦截
  - DOMAIN-SUFFIX,channeladvisor.com,🛑 全球拦截
  - DOMAIN-SUFFIX,connexity.net,🛑 全球拦截
  - DOMAIN-SUFFIX,criteo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,criteo.net,🛑 全球拦截
  - DOMAIN-SUFFIX,csbew.com,🛑 全球拦截
  - DOMAIN-SUFFIX,directrev.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dumedia.ru,🛑 全球拦截
  - DOMAIN-SUFFIX,effectivemeasure.com,🛑 全球拦截
  - DOMAIN-SUFFIX,effectivemeasure.net,🛑 全球拦截
  - DOMAIN-SUFFIX,eqads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,everesttech.net,🛑 全球拦截
  - DOMAIN-SUFFIX,exoclick.com,🛑 全球拦截
  - DOMAIN-SUFFIX,extend.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,eyereturn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fastapi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,fastclick.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fastclick.net,🛑 全球拦截
  - DOMAIN-SUFFIX,flurry.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gosquared.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gtags.net,🛑 全球拦截
  - DOMAIN-SUFFIX,heyzap.com,🛑 全球拦截
  - DOMAIN-SUFFIX,histats.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hitslink.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hot-mob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hyperpromote.com,🛑 全球拦截
  - DOMAIN-SUFFIX,i-mobile.co.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,imrworldwide.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inner-active.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,intentiq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inter1ads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ipredictive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ironsrc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iskyworker.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jizzads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,juicyads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kochava.com,🛑 全球拦截
  - DOMAIN-SUFFIX,leadbolt.com,🛑 全球拦截
  - DOMAIN-SUFFIX,leadbolt.net,🛑 全球拦截
  - DOMAIN-SUFFIX,leadboltads.net,🛑 全球拦截
  - DOMAIN-SUFFIX,leadboltapps.net,🛑 全球拦截
  - DOMAIN-SUFFIX,leadboltmobile.net,🛑 全球拦截
  - DOMAIN-SUFFIX,lenzmx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,liveadvert.com,🛑 全球拦截
  - DOMAIN-SUFFIX,marketgid.com,🛑 全球拦截
  - DOMAIN-SUFFIX,marketo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mdotm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,medialytics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,medialytics.io,🛑 全球拦截
  - DOMAIN-SUFFIX,meetrics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,meetrics.net,🛑 全球拦截
  - DOMAIN-SUFFIX,mgid.com,🛑 全球拦截
  - DOMAIN-SUFFIX,millennialmedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobadme.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,mobfox.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobileadtrading.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobilityware.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mojiva.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mookie1.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msads.net,🛑 全球拦截
  - DOMAIN-SUFFIX,mydas.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,nend.net,🛑 全球拦截
  - DOMAIN-SUFFIX,netshelter.net,🛑 全球拦截
  - DOMAIN-SUFFIX,nexage.com,🛑 全球拦截
  - DOMAIN-SUFFIX,owneriq.net,🛑 全球拦截
  - DOMAIN-SUFFIX,pixels.asia,🛑 全球拦截
  - DOMAIN-SUFFIX,plista.com,🛑 全球拦截
  - DOMAIN-SUFFIX,popads.net,🛑 全球拦截
  - DOMAIN-SUFFIX,powerlinks.com,🛑 全球拦截
  - DOMAIN-SUFFIX,propellerads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,quantserve.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rayjump.com,🛑 全球拦截
  - DOMAIN-SUFFIX,revdepo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rubiconproject.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sape.ru,🛑 全球拦截
  - DOMAIN-SUFFIX,scorecardresearch.com,🛑 全球拦截
  - DOMAIN-SUFFIX,segment.com,🛑 全球拦截
  - DOMAIN-SUFFIX,serving-sys.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sharethis.com,🛑 全球拦截
  - DOMAIN-SUFFIX,smaato.com,🛑 全球拦截
  - DOMAIN-SUFFIX,smaato.net,🛑 全球拦截
  - DOMAIN-SUFFIX,smartadserver.com,🛑 全球拦截
  - DOMAIN-SUFFIX,smartnews-ads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,startapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,startappexchange.com,🛑 全球拦截
  - DOMAIN-SUFFIX,statcounter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,steelhousemedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stickyadstv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,supersonic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,taboola.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tapjoy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tapjoyads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,trafficjunky.com,🛑 全球拦截
  - DOMAIN-SUFFIX,trafficjunky.net,🛑 全球拦截
  - DOMAIN-SUFFIX,tribalfusion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,turn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uberads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vidoomy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,viglink.com,🛑 全球拦截
  - DOMAIN-SUFFIX,voicefive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wedolook.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yadro.ru,🛑 全球拦截
  - DOMAIN-SUFFIX,yengo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zedo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zemanta.com,🛑 全球拦截
  - DOMAIN-SUFFIX,11h5.com,🛑 全球拦截
  - DOMAIN-SUFFIX,1kxun.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,26zsd.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,519397.com,🛑 全球拦截
  - DOMAIN-SUFFIX,626uc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,915.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appget.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,appuu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,coinhive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,huodonghezi.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,vcbn65.xyz,🛑 全球拦截
  - DOMAIN-SUFFIX,wanfeng1.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wep016.top,🛑 全球拦截
  - DOMAIN-SUFFIX,win-stock.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zantainet.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dh54wf.xyz,🛑 全球拦截
  - DOMAIN-SUFFIX,g2q3e.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,114so.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,go.10086.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hivedata.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,navi.gd.chinamobile.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adgeo.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.126.net,🛑 全球拦截
  - DOMAIN-SUFFIX,bobo.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clkservice.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,conv.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dsp-impr2.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dsp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fa.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g1.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gb.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gorgon.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,haitaoad.nosdn.127.net,🛑 全球拦截
  - DOMAIN-SUFFIX,iadmatvideo.nosdn.127.net,🛑 全球拦截
  - DOMAIN-SUFFIX,img1.126.net,🛑 全球拦截
  - DOMAIN-SUFFIX,img2.126.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ir.mail.126.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ir.mail.yeah.net,🛑 全球拦截
  - DOMAIN-SUFFIX,mimg.126.net,🛑 全球拦截
  - DOMAIN-SUFFIX,nc004x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nc045x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nex.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,oimagea2.ydstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pagechoice.net,🛑 全球拦截
  - DOMAIN-SUFFIX,prom.gome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,qchannel0d.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,qt002x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rlogs.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,static.flv.uuzuonline.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tb060x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tb104x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wanproxy.127.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ydpushserver.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cvda.17173.com,🛑 全球拦截
  - DOMAIN-SUFFIX,imgapp.yeyou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log1.17173.com,🛑 全球拦截
  - DOMAIN-SUFFIX,s.17173cdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ue.yeyoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vda.17173.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.wanmei.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gg.stargame.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,download.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,houtai.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jifen.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jifendownload.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,minipage.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zhushou.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,3600.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gamebox.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jiagu.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,kuaikan.netmon.360safe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,leak.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,lianmeng.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pub.se.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,s.so.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,shouji.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,soft.data.weather.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.360safe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.m.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,update.360safe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,58.xgo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,brandshow.58.com,🛑 全球拦截
  - DOMAIN-SUFFIX,imp.xgo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jing.58.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.xgo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,track.58.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tracklog.58.com,🛑 全球拦截
  - DOMAIN-SUFFIX,acjs.aliyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adash-c.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adash-c.ut.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adashx4yt.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adashxgc.ut.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afp.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ai.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,alipaylog.com,🛑 全球拦截
  - DOMAIN-SUFFIX,atanx.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,atanx2.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fav.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.click.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.tbcdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gma.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gtmsdd.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hydra.alibaba.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pindao.huoban.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,re.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,redirect.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rj.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdkinit.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,show.re.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,simaba.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,simaba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,srd.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,strip.taobaocdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tns.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tyh.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,userimg.qunar.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yiliao.hupan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,3dns-2.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,3dns-3.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,activate-sea.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,activate-sjc0.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,activate.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adobe-dns-2.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adobe-dns-3.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adobe-dns.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ereg.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,geo2.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hl2rcv.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hlrcv.stage.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lm.licenses.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lmlicenses.wip4.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,na1r.services.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,na2m-pr.licenses.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,practivate.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wip3.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wwis-dubc1-vip60.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adserver.unityads.unity3d.com,🛑 全球拦截
  - DOMAIN-SUFFIX,33.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adproxy.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,al.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,alert.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,applogapi.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,c.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cmx.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dspmnt.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pcd.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,push.app.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pvx.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rd.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rdx.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,stats.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,a.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,a.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.duapps.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.player.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adscdn.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adscdn.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adx.xiaodutv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ae.bdstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afd.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,afd.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,als.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,als.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,anquan.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,anquan.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,antivirus.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api.mobula.sdk.duapps.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appc.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,appc.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,as.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,as.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baichuan.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baidu9635.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baidutv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,banlv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bar.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bdplus.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,btlaunch.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,c.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cb.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cb.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cbjs.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cbjs.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cbjslog.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cbjslog.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cjhq.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cjhq.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cleaner.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.bes.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.hm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.qianqian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.tieba.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.zhidao.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro2.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro2.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpu-admin.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,crs.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,crs.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,datax.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl-vip.bav.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl-vip.pcfaster.baidu.co.th,🛑 全球拦截
  - DOMAIN-SUFFIX,dl.client.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl.ops.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl1sw.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl2.bav.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dlsw.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dlsw.br.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,download.bav.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,download.sd.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,drmcmm.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,drmcmm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dup.baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dxp.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dzl.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,e.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,e.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,eclick.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,eclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ecma.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ecmb.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ecmc.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,eiv.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,eiv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,em.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ers.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,f10.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fc-.cdn.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fc-feed.cdn.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fexclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gimg.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,guanjia.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hc.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hc.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hm.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hmma.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hmma.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hpd.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hpd.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,idm-su.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iebar.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ikcode.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,imageplus.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,imageplus.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,img.taotaosou.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,img01.taotaosou.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,itsdata.map.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,j.br.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kstj.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.music.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.nuomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m1.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ma.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ma.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mg09.zhaopin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mipcache.bdstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobads-logs.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobads-logs.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobads.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobads.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mpro.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mtj.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mtj.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,neirong.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nsclick.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,nsclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nsclickvideo.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,openrcv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pc.videoclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pos.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pups.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pups.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pups.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.music.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.zhanzhang.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qchannel0d.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,qianclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,release.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,res.limei.com,🛑 全球拦截
  - DOMAIN-SUFFIX,res.mi.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rigel.baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,river.zhidao.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rj.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rj.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rp.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rp.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rplog.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,s.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sestat.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shadu.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,share.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sobar.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sobartop.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,spcode.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,spcode.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.v.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,su.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,su.bdstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tk.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,tk.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tkweb.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tob-cms.bj.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,toolbar.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tracker.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tuijian.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tuisong.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,tuisong.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ubmcmm.baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ucstat.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ucstat.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ulic.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ulog.imap.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,union.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,unionimage.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,utility.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,utility.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,utk.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,utk.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,videopush.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,videopush.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vv84.bj.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,w.gdown.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,w.x.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wangmeng.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wangmeng.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,weishi.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wenku-cms.bj.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wisepush.video.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wm.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,znsv.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,znsv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zz.bdstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zzy1.quyaoya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.zhangyue.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.ps.easou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aishowbger.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api.itaoxiaoshuo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,assets.ps.easou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bbcoe.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cj.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dkeyn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,drdwy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,e.aa985.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,e.v02u9.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,e701.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ehxyz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ethod.gzgmjcx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,focuscat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hdswgc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jyd.fjzdmy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.ourlj.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.txtxr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.vsxet.com,🛑 全球拦截
  - DOMAIN-SUFFIX,miam4.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,o.if.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.vq6nsu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,picture.duokan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.zhangyue.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pyerc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,s1.cmfu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sc.shayugg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdk.cferw.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sezvc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sys.zhangyue.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tjlog.ps.easou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tongji.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ut2.shuqistat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xgcsr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xjq.jxmqkj.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xpe.cxaerp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xtzxmy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xyrkl.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zhuanfakong.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dsp.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ic.snssdk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.snssdk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nativeapp.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pangolin-sdk-toutiao-b.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pangolin-sdk-toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pangolin.snssdk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,partner.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pglstatp-toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sm.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a.dangdang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.dangdang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,schprompt.dangdang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,t.dangdang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.duomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,boxshows.com,🛑 全球拦截
  - DOMAIN-SUFFIX,staticxx.facebook.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click1n.soufun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clickm.fang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clickn.fang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,countpvn.light.fang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,countubn.light.soufun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mshow.fang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tongji.home.soufun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.gmodules.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adservice.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afd.l.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,badad.googleplex.com,🛑 全球拦截
  - DOMAIN-SUFFIX,csi.gstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doubleclick.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doubleclick.net,🛑 全球拦截
  - DOMAIN-SUFFIX,google-analytics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,googleadservices.com,🛑 全球拦截
  - DOMAIN-SUFFIX,googleadsserving.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,googlecommerce.com,🛑 全球拦截
  - DOMAIN-SUFFIX,googlesyndication.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobileads.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pagead-tpc.l.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pagead.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pagead.l.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,service.urchin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.union.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c-nfa.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cps.360buy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,img-x.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jrclick.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jzt.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,policy.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.m.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.service.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsfile.bssdlbig.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,d.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,downmobile.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gad.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gamebox.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gcapi.sy.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gg.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,install.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,install2.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kgmobilestat.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kuaikaiapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.stat.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.web.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,minidcsc.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mo.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobilelog.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msg.mobile.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mvads.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.mobile.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rtmonitor.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdn.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tj.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,update.mobile.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,apk.shouji.koowo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,deliver.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,g.koowo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,kwmsg.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,log.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobilead.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,msclick2.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,msphoneclick.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,updatepage.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wa.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,webstat.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,aider-res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-flow.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-game.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-push.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aries.mzres.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bro.flyme.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cal.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ebook.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ebook.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game-res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,infocenter.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,openapi-news.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,reader.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,reader.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,t-e.flyme.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,t-flow.flyme.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,tongji-res1.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tongji.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,umid.orion.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,upush.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uxip.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a.koudai.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adui.tg.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,corp.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dc.meitustat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gg.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mdc.meitustat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,meitubeauty.meitudata.com,🛑 全球拦截
  - DOMAIN-SUFFIX,message.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rabbit.meitustat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rabbit.tg.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tuiguang.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xiuxiu.android.dl.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xiuxiu.mobile.meitudata.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a.market.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad1.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adv.sec.intl.miui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adv.sec.miui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bss.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,d.g.mi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,data.mistat.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,de.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dvb.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jellyfish.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,migc.g.mi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,migcreport.g.mi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,notice.game.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ppurifier.game.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,r.browser.miui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,security.browser.miui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shenghuo.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union.mi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wtradv.market.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.api.moji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,app.moji001.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cdn.moji002.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cdn2.moji002.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fds.api.moji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.moji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.moji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ugc.moji001.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,admgr.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,dload.qd.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,logger.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,s.qd.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,s.qd.qingtingfm.com,🛑 全球拦截
  - DOMAIN-KEYWORD,omgmtaw,🛑 全球拦截
  - DOMAIN,adsmind.apdcdn.tc.qq.com,🛑 全球拦截
  - DOMAIN,adsmind.gdtimg.com,🛑 全球拦截
  - DOMAIN,adsmind.tc.qq.com,🛑 全球拦截
  - DOMAIN,pgdt.gtimg.cn,🛑 全球拦截
  - DOMAIN,pgdt.gtimg.com,🛑 全球拦截
  - DOMAIN,pgdt.ugdtimg.com,🛑 全球拦截
  - DOMAIN,splashqqlive.gtimg.com,🛑 全球拦截
  - DOMAIN,wa.gtimg.com,🛑 全球拦截
  - DOMAIN,wxsnsdy.wxs.qq.com,🛑 全球拦截
  - DOMAIN,wxsnsdythumb.wxs.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,act.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.qun.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsfile.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bugly.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,buluo.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,e.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gdt.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,monitor.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pingma.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pingtcss.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,report.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tajs.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tcss.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uu.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ebp.renren.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jebe.renren.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jebe.xnimg.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adbox.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,add.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adimg.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,alitui.weibo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,biz.weibo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cre.dp.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dcads.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dd.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dmp.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,game.weibo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gw5.push.mcp.weibo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,leju.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,log.mix.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobileads.dx.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,newspush.sinajs.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pay.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,sax.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,sax.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,saxd.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,sdkapp.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,sdkapp.uve.weibo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdkclick.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,slog.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,trends.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,tui.weibo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,u1.img.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wax.weibo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wbapp.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wbapp.uve.weibo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wbclick.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wbpctips.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zymo.mps.weibo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,123.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,123.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsence.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,amfi.gou.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,brand.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpc.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,epro.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fair.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,files2.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,galaxy.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,golden1.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,goto.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inte.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iwan.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lu.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lu.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pb.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pd.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,theta.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wangmeng.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,applovin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,guangzhuiyuan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads-twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,scribe.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,syndication-o.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,syndication.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tellapart.com,🛑 全球拦截
  - DOMAIN-SUFFIX,urls.api.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adslot.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,api.mp.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,applog.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,client.video.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cms.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dispatcher.upmc.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,huichuan.sm.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,log.cs.pp.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,m.uczzd.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,patriot.cs.pp.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,puds.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,server.m.pp.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,track.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,u.uc123.com,🛑 全球拦截
  - DOMAIN-SUFFIX,u.ucfly.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uc.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ucsec.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ucsec1.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aoodoo.feng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fengbuy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.feng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,we.tm,🛑 全球拦截
  - DOMAIN-SUFFIX,yes1.feng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.docer.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.zookingsoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bannera.kingsoft-office-service.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bole.shangshufang.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,counter.kingsoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,docerad.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gou.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hoplink.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ic.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,img.gou.wpscdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,info.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ios-informationplatform.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,minfo.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mo.res.wpscdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,news.docer.com,🛑 全球拦截
  - DOMAIN-SUFFIX,notify.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pc.uf.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pcfg.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pixiu.shangshufang.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rating6.kingsoft-office-service.com,🛑 全球拦截
  - DOMAIN-SUFFIX,up.wps.kingsoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wpsweb-dc.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,c.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,cdsget.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,news-imgpb.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,wifiapidd.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,wkanc.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adse.ximalaya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,linkeye.ximalaya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,location.ximalaya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xdcs-collector.ximalaya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,biz5.kankan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,float.kankan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hub5btmain.sandai.net,🛑 全球拦截
  - DOMAIN-SUFFIX,hub5emu.sandai.net,🛑 全球拦截
  - DOMAIN-SUFFIX,logic.cpm.cm.kankan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,upgrade.xl9.xunlei.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.wretch.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adserver.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adss.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.query.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ane.yahoo.co.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,ard.yahoo.co.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,beap-bc.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clicks.beap.bc.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,comet.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doubleplay-conf-yql.media.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,flurry.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gemini.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,geo.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,js-apac-ss.ysm.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,locdrop.query.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,onepush.query.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p3p.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,partnerads.ysm.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ws.progrss.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yads.yahoo.co.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,ybp.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shrek.6.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,simba.6.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,union.6.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,logger.baofeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xs.houyi.baofeng.net,🛑 全球拦截
  - DOMAIN-SUFFIX,dotcounter.douyutv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api.newad.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,exp.3g.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iis3g.deliver.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mfp.deliver.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stadig.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jobsfe.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,po.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pub.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.m.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afp.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.uaa.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cloudpush.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cm.passport.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cupid.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,emoticon.sns.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gamecenter.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ifacelog.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mbdlog.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,meta.video.qiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msg.71.am,🛑 全球拦截
  - DOMAIN-SUFFIX,msg1.video.qiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msg2.video.qiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,paopao.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,paopaod.qiyipic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,policy.video.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yuedu.iqiyi.com,🛑 全球拦截
  - IP-CIDR,101.227.200.0/24,🛑 全球拦截,no-resolve
  - IP-CIDR,101.227.200.11/32,🛑 全球拦截,no-resolve
  - IP-CIDR,101.227.200.28/32,🛑 全球拦截,no-resolve
  - IP-CIDR,101.227.97.240/32,🛑 全球拦截,no-resolve
  - IP-CIDR,124.192.153.42/32,🛑 全球拦截,no-resolve
  - DOMAIN-SUFFIX,gug.ku6cdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pq.stat.ku6.com,🛑 全球拦截
  - DOMAIN-SUFFIX,st.vq.ku6.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,static.ku6.com,🛑 全球拦截
  - DOMAIN-SUFFIX,1.letvlive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,2.letvlive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ark.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dc.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fz.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g3.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.letvstore.com,🛑 全球拦截
  - DOMAIN-SUFFIX,i0.letvimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,i3.letvimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,minisite.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,n.mark.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pro.hoye.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pro.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,static.app.m.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,da.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,da.mgtv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.v2.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p2.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,res.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,888.tv.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adnet.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aty.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aty.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bd.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click2.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ctr.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,epro.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,epro.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,go.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,golden1.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,golden1.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hui.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inte.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inte.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inte.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lm.tv.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lu.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pb.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.tv.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,theta.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,um.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uranus.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uranus.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wl.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yule.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afp.pplive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,app.aplus.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,as.aplus.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,asimgs.pplive.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,de.as.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jp.as.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pp2.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,btrace.video.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dp3.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,livep.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lives.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,livew.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mcgi.v.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mdevstat.qqlive.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,omgmta1.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rcgi.video.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,t.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,u.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a-dxk.play.api.3g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,actives.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.api.3g.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.api.3g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.api.mobile.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.mobile.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adcontrol.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adplay.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,b.smartvideo.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.yes.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dev-push.m.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl.g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dmapp.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,e.stat.ykimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gamex.mobile.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,goods.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hudong.pl.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hz.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iwstat.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iyes.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,l.ykimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,l.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lstat.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lvip.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobilemsg.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msg.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,myes.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nstat.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p-log.ykimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.l.ykimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.l.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,passport-log.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.m.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,r.l.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,s.p.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdk.m.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stats.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,store.tv.api.3g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,store.xl.api.3g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tdrec.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,test.ott.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,v.l.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,val.api.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ykatr.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ykrec.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ykrectab.youku.com,🛑 全球拦截
  - IP-CIDR,117.177.248.17/32,🛑 全球拦截,no-resolve
  - IP-CIDR,117.177.248.41/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.176.139/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.176.176/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.180/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.182/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.184/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.43/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.47/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.80/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.182.101/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.182.102/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.182.11/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.182.52/32,🛑 全球拦截,no-resolve
  - DOMAIN-SUFFIX,azabu-u.ac.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,couchcoaster.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,delivery.dmkt-sp.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,ehg-youtube.hitbox.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nichibenren.or.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,nicorette.co.kr,🛑 全球拦截
  - DOMAIN-SUFFIX,ssl-youtube.2cnt.net,🛑 全球拦截
  - DOMAIN-SUFFIX,youtube.112.2o7.net,🛑 全球拦截
  - DOMAIN-SUFFIX,youtube.2cnt.net,🛑 全球拦截
  - DOMAIN-SUFFIX,acsystem.wasu.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.cdn.tvb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.wasu.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,afp.wasu.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,c.algovid.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gg.jtertp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gridsum-vd.cntv.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,kwflvcdn.000dn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,logstat.t.sfht.com,🛑 全球拦截
  - DOMAIN-SUFFIX,match.rtbidder.net,🛑 全球拦截
  - DOMAIN-SUFFIX,n-st.vip.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pop.uusee.com,🛑 全球拦截
  - DOMAIN-SUFFIX,static.duoshuo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,t.cr-nielsen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,terren.cntv.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,1.win7china.com,🛑 全球拦截
  - DOMAIN-SUFFIX,168.it168.com,🛑 全球拦截
  - DOMAIN-SUFFIX,2.win7china.com,🛑 全球拦截
  - DOMAIN-SUFFIX,801.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,801.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,803.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,803.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,806.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,806.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,808.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,808.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,92x.tumblr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a1.itc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-channel.wikawika.xyz,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-display.wikawika.xyz,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.12306.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.3.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.95306.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.caiyunapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.cctv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.cmvideo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.csdn.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.house365.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.thepaper.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.unimhk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adadmin.house365.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adhome.1fangchan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.csdn.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.feedly.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.genieessp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.house365.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.linkedin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adshownew.it168.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adv.ccb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,advert.api.thejoyrun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-deal.kechenggezi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-z.weidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,app-monitor.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,bat.bing.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bd1.52che.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bd2.52che.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bdj.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,bdj.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,beacon.tingyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cdn.jiuzhilan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.cheshi-img.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.cheshi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,click.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,client-api.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,collector.githubapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,counter.csdn.net,🛑 全球拦截
  - DOMAIN-SUFFIX,d0.xcar.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,de.soquair.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dol.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dol.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dw.xcar.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,e.nexac.com,🛑 全球拦截
  - DOMAIN-SUFFIX,eq.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,exp.17wo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,game.51yund.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ganjituiguang.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,grand.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,hosting.miarroba.info,🛑 全球拦截
  - DOMAIN-SUFFIX,iadsdk.apple.com,🛑 全球拦截
  - DOMAIN-SUFFIX,image.gentags.com,🛑 全球拦截
  - DOMAIN-SUFFIX,its-dori.tumblr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.outbrain.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.12306media.com,🛑 全球拦截
  - DOMAIN-SUFFIX,media.cheshi-img.com,🛑 全球拦截
  - DOMAIN-SUFFIX,media.cheshi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobile-pubt.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,mobileads.msn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,n.cosbot.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,newton-api.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,ozone.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pdl.gionee.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pica-juicy.picacomic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pixel.wp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pub.mop.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.wandoujia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.cheshi-img.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.cheshi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.xcar.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,qdp.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,res.gwifi.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ssp.kssws.ks-cdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sta.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.it168.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stats.chinaz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stats.developingperspective.com,🛑 全球拦截
  - DOMAIN-SUFFIX,track.hujiang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tracker.yhd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tralog.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,up.qingdaonews.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vaserviece.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,265.com,选择代理
  - DOMAIN-SUFFIX,2mdn.net,选择代理
  - DOMAIN-SUFFIX,alt1-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt2-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt3-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt4-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt5-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt6-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt7-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt8-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,app-measurement.com,选择代理
  - DOMAIN-SUFFIX,cache.pack.google.com,选择代理
  - DOMAIN-SUFFIX,clickserve.dartsearch.net,选择代理
  - DOMAIN-SUFFIX,crl.pki.goog,选择代理
  - DOMAIN-SUFFIX,dl.google.com,选择代理
  - DOMAIN-SUFFIX,dl.l.google.com,选择代理
  - DOMAIN-SUFFIX,googletagmanager.com,选择代理
  - DOMAIN-SUFFIX,googletagservices.com,选择代理
  - DOMAIN-SUFFIX,gtm.oasisfeng.com,选择代理
  - DOMAIN-SUFFIX,mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,ocsp.pki.goog,选择代理
  - DOMAIN-SUFFIX,recaptcha.net,选择代理
  - DOMAIN-SUFFIX,safebrowsing-cache.google.com,选择代理
  - DOMAIN-SUFFIX,settings.crashlytics.com,选择代理
  - DOMAIN-SUFFIX,ssl-google-analytics.l.google.com,选择代理
  - DOMAIN-SUFFIX,toolbarqueries.google.com,选择代理
  - DOMAIN-SUFFIX,tools.google.com,选择代理
  - DOMAIN-SUFFIX,tools.l.google.com,选择代理
  - DOMAIN-SUFFIX,www-googletagmanager.l.google.com,选择代理
  - DOMAIN,csgo.wmsj.cn,选择代理
  - DOMAIN,dl.steam.clngaa.com,选择代理
  - DOMAIN,dl.steam.ksyna.com,选择代理
  - DOMAIN,dota2.wmsj.cn,选择代理
  - DOMAIN,st.dl.bscstorage.net,选择代理
  - DOMAIN,st.dl.eccdnx.com,选择代理
  - DOMAIN,st.dl.pinyuncloud.com,选择代理
  - DOMAIN,steampipe.steamcontent.tnkjmec.com,选择代理
  - DOMAIN,steampowered.com.8686c.com,选择代理
  - DOMAIN,steamstatic.com.8686c.com,选择代理
  - DOMAIN,wmsjsteam.com,选择代理
  - DOMAIN,xz.pphimalayanrt.com,选择代理
  - DOMAIN-SUFFIX,cm.steampowered.com,选择代理
  - DOMAIN-SUFFIX,steamchina.com,选择代理
  - DOMAIN-SUFFIX,steamcontent.com,选择代理
  - DOMAIN-SUFFIX,steamusercontent.com,选择代理
  - DOMAIN-SUFFIX,t.me,选择代理
  - DOMAIN-SUFFIX,tdesktop.com,选择代理
  - DOMAIN-SUFFIX,telegra.ph,选择代理
  - DOMAIN-SUFFIX,telegram.me,选择代理
  - DOMAIN-SUFFIX,telegram.org,选择代理
  - DOMAIN-SUFFIX,telesco.pe,选择代理
  - IP-CIDR,91.108.0.0/16,选择代理,no-resolve
  - IP-CIDR,95.161.64.0/20,选择代理,no-resolve
  - IP-CIDR,109.239.140.0/24,选择代理,no-resolve
  - IP-CIDR,149.154.160.0/20,选择代理,no-resolve
  - IP-CIDR6,2001:67c:4e8::/48,选择代理,no-resolve
  - IP-CIDR6,2001:b28:f23d::/48,选择代理,no-resolve
  - IP-CIDR6,2001:b28:f23f::/48,选择代理,no-resolve
  - DOMAIN-SUFFIX,edgedatg.com,选择代理
  - DOMAIN-SUFFIX,go.com,选择代理
  - DOMAIN-KEYWORD,abematv.akamaized.net,选择代理
  - DOMAIN-SUFFIX,abema.io,选择代理
  - DOMAIN-SUFFIX,abema.tv,选择代理
  - DOMAIN-SUFFIX,ameba.jp,选择代理
  - DOMAIN-SUFFIX,hayabusa.io,选择代理
  - DOMAIN-SUFFIX,c4assets.com,选择代理
  - DOMAIN-SUFFIX,channel4.com,选择代理
  - DOMAIN-KEYWORD,avoddashs,选择代理
  - DOMAIN,atv-ps.amazon.com,选择代理
  - DOMAIN,avodmp4s3ww-a.akamaihd.net,选择代理
  - DOMAIN,d1v5ir2lpwr8os.cloudfront.net,选择代理
  - DOMAIN,d1xfray82862hr.cloudfront.net,选择代理
  - DOMAIN,d22qjgkvxw22r6.cloudfront.net,选择代理
  - DOMAIN,d25xi40x97liuc.cloudfront.net,选择代理
  - DOMAIN,d27xxe7juh1us6.cloudfront.net,选择代理
  - DOMAIN,d3196yreox78o9.cloudfront.net,选择代理
  - DOMAIN,dmqdd6hw24ucf.cloudfront.net,选择代理
  - DOMAIN,ktpx.amazon.com,选择代理
  - DOMAIN-SUFFIX,aboutamazon.com,选择代理
  - DOMAIN-SUFFIX,aiv-cdn.net,选择代理
  - DOMAIN-SUFFIX,aiv-delivery.net,选择代理
  - DOMAIN-SUFFIX,amazon.jobs,选择代理
  - DOMAIN-SUFFIX,amazontools.com,选择代理
  - DOMAIN-SUFFIX,amazontours.com,选择代理
  - DOMAIN-SUFFIX,amazonuniversity.jobs,选择代理
  - DOMAIN-SUFFIX,amazonvideo.com,选择代理
  - DOMAIN-SUFFIX,media-amazon.com,选择代理
  - DOMAIN-SUFFIX,pv-cdn.net,选择代理
  - DOMAIN-SUFFIX,seattlespheres.com,选择代理
  - DOMAIN,gspe1-ssl.ls.apple.com,选择代理
  - DOMAIN,np-edge.itunes.apple.com,选择代理
  - DOMAIN,play-edge.itunes.apple.com,选择代理
  - DOMAIN-SUFFIX,tv.apple.com,选择代理
  - DOMAIN-KEYWORD,bbcfmt,选择代理
  - DOMAIN-KEYWORD,uk-live,选择代理
  - DOMAIN,aod-dash-uk-live.akamaized.net,选择代理
  - DOMAIN,aod-hls-uk-live.akamaized.net,选择代理
  - DOMAIN,vod-dash-uk-live.akamaized.net,选择代理
  - DOMAIN,vod-thumb-uk-live.akamaized.net,选择代理
  - DOMAIN-SUFFIX,bbc.co,选择代理
  - DOMAIN-SUFFIX,bbc.co.uk,选择代理
  - DOMAIN-SUFFIX,bbc.com,选择代理
  - DOMAIN-SUFFIX,bbc.net.uk,选择代理
  - DOMAIN-SUFFIX,bbcfmt.hs.llnwd.net,选择代理
  - DOMAIN-SUFFIX,bbci.co,选择代理
  - DOMAIN-SUFFIX,bbci.co.uk,选择代理
  - DOMAIN-SUFFIX,bidi.net.uk,选择代理
  - DOMAIN,bahamut.akamaized.net,选择代理
  - DOMAIN,gamer-cds.cdn.hinet.net,选择代理
  - DOMAIN,gamer2-cds.cdn.hinet.net,选择代理
  - DOMAIN-SUFFIX,bahamut.com.tw,选择代理
  - DOMAIN-SUFFIX,gamer.com.tw,选择代理
  - DOMAIN-KEYWORD,voddazn,选择代理
  - DOMAIN,d151l6v8er5bdm.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,d151l6v8er5bdm.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,d1sgwhnao7452x.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,dazn-api.com,选择代理
  - DOMAIN-SUFFIX,dazn.com,选择代理
  - DOMAIN-SUFFIX,dazndn.com,选择代理
  - DOMAIN-SUFFIX,dcblivedazn.akamaized.net,选择代理
  - DOMAIN-SUFFIX,indazn.com,选择代理
  - DOMAIN-SUFFIX,indaznlab.com,选择代理
  - DOMAIN-SUFFIX,sentry.io,选择代理
  - DOMAIN-SUFFIX,deezer.com,选择代理
  - DOMAIN-SUFFIX,dzcdn.net,选择代理
  - DOMAIN-SUFFIX,disco-api.com,选择代理
  - DOMAIN-SUFFIX,discovery.com,选择代理
  - DOMAIN-SUFFIX,uplynk.com,选择代理
  - DOMAIN,cdn.registerdisney.go.com,选择代理
  - DOMAIN-SUFFIX,adobedtm.com,选择代理
  - DOMAIN-SUFFIX,bam.nr-data.net,选择代理
  - DOMAIN-SUFFIX,bamgrid.com,选择代理
  - DOMAIN-SUFFIX,braze.com,选择代理
  - DOMAIN-SUFFIX,cdn.optimizely.com,选择代理
  - DOMAIN-SUFFIX,cdn.registerdisney.go.com,选择代理
  - DOMAIN-SUFFIX,cws.conviva.com,选择代理
  - DOMAIN-SUFFIX,d9.flashtalking.com,选择代理
  - DOMAIN-SUFFIX,disney-plus.net,选择代理
  - DOMAIN-SUFFIX,disney-portal.my.onetrust.com,选择代理
  - DOMAIN-SUFFIX,disney.demdex.net,选择代理
  - DOMAIN-SUFFIX,disney.my.sentry.io,选择代理
  - DOMAIN-SUFFIX,disneyplus.bn5x.net,选择代理
  - DOMAIN-SUFFIX,disneyplus.com,选择代理
  - DOMAIN-SUFFIX,disneyplus.com.ssl.sc.omtrdc.net,选择代理
  - DOMAIN-SUFFIX,disneystreaming.com,选择代理
  - DOMAIN-SUFFIX,dssott.com,选择代理
  - DOMAIN-SUFFIX,execute-api.us-east-1.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,js-agent.newrelic.com,选择代理
  - DOMAIN,bcbolt446c5271-a.akamaihd.net,选择代理
  - DOMAIN,content.jwplatform.com,选择代理
  - DOMAIN,edge.api.brightcove.com,选择代理
  - DOMAIN,videos-f.jwpsrv.com,选择代理
  - DOMAIN-SUFFIX,encoretvb.com,选择代理
  - DOMAIN-SUFFIX,fox.com,选择代理
  - DOMAIN-SUFFIX,foxdcg.com,选择代理
  - DOMAIN-SUFFIX,uplynk.com,选择代理
  - DOMAIN-SUFFIX,hbo.com,选择代理
  - DOMAIN-SUFFIX,hbogo.com,选择代理
  - DOMAIN-SUFFIX,hbomax.com,选择代理
  - DOMAIN-SUFFIX,hbomaxcdn.com,选择代理
  - DOMAIN-SUFFIX,hbonow.com,选择代理
  - DOMAIN-KEYWORD,hbogoasia,选择代理
  - DOMAIN,44wilhpljf.execute-api.ap-southeast-1.amazonaws.com,选择代理
  - DOMAIN,bcbolthboa-a.akamaihd.net,选择代理
  - DOMAIN,cf-images.ap-southeast-1.prod.boltdns.net,选择代理
  - DOMAIN,dai3fd1oh325y.cloudfront.net,选择代理
  - DOMAIN,hboasia1-i.akamaihd.net,选择代理
  - DOMAIN,hboasia2-i.akamaihd.net,选择代理
  - DOMAIN,hboasia3-i.akamaihd.net,选择代理
  - DOMAIN,hboasia4-i.akamaihd.net,选择代理
  - DOMAIN,hboasia5-i.akamaihd.net,选择代理
  - DOMAIN,hboasialive.akamaized.net,选择代理
  - DOMAIN,hbogoprod-vod.akamaized.net,选择代理
  - DOMAIN,hbolb.onwardsmg.com,选择代理
  - DOMAIN,hbounify-prod.evergent.com,选择代理
  - DOMAIN,players.brightcove.net,选择代理
  - DOMAIN,s3-ap-southeast-1.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,hboasia.com,选择代理
  - DOMAIN-SUFFIX,hbogoasia.com,选择代理
  - DOMAIN-SUFFIX,hbogoasia.hk,选择代理
  - DOMAIN-SUFFIX,5itv.tv,选择代理
  - DOMAIN-SUFFIX,ocnttv.com,选择代理
  - DOMAIN-SUFFIX,cws-hulu.conviva.com,选择代理
  - DOMAIN-SUFFIX,hulu.com,选择代理
  - DOMAIN-SUFFIX,hulu.hb.omtrdc.net,选择代理
  - DOMAIN-SUFFIX,hulu.sc.omtrdc.net,选择代理
  - DOMAIN-SUFFIX,huluad.com,选择代理
  - DOMAIN-SUFFIX,huluim.com,选择代理
  - DOMAIN-SUFFIX,hulustream.com,选择代理
  - DOMAIN-SUFFIX,happyon.jp,选择代理
  - DOMAIN-SUFFIX,hjholdings.jp,选择代理
  - DOMAIN-SUFFIX,hulu.jp,选择代理
  - DOMAIN-SUFFIX,prod.hjholdings.tv,选择代理
  - DOMAIN-SUFFIX,streaks.jp,选择代理
  - DOMAIN-SUFFIX,yb.uncn.jp,选择代理
  - DOMAIN,itvpnpmobile-a.akamaihd.net,选择代理
  - DOMAIN-SUFFIX,itv.com,选择代理
  - DOMAIN-SUFFIX,itvstatic.com,选择代理
  - DOMAIN-SUFFIX,iwara.tv,选择代理
  - DOMAIN-KEYWORD,jooxweb-api,选择代理
  - DOMAIN-SUFFIX,joox.com,选择代理
  - DOMAIN-KEYWORD,japonx,选择代理
  - DOMAIN-KEYWORD,japronx,选择代理
  - DOMAIN-SUFFIX,japonx.com,选择代理
  - DOMAIN-SUFFIX,japonx.net,选择代理
  - DOMAIN-SUFFIX,japonx.tv,选择代理
  - DOMAIN-SUFFIX,japonx.vip,选择代理
  - DOMAIN-SUFFIX,japronx.com,选择代理
  - DOMAIN-SUFFIX,japronx.net,选择代理
  - DOMAIN-SUFFIX,japronx.tv,选择代理
  - DOMAIN-SUFFIX,japronx.vip,选择代理
  - DOMAIN-SUFFIX,kfs.io,选择代理
  - DOMAIN-SUFFIX,kkbox.com,选择代理
  - DOMAIN-SUFFIX,kkbox.com.tw,选择代理
  - DOMAIN,kktv-theater.kk.stream,选择代理
  - DOMAIN,theater-kktv.cdn.hinet.net,选择代理
  - DOMAIN-SUFFIX,kktv.com.tw,选择代理
  - DOMAIN-SUFFIX,kktv.me,选择代理
  - DOMAIN,litvfreemobile-hichannel.cdn.hinet.net,选择代理
  - DOMAIN-SUFFIX,litv.tv,选择代理
  - DOMAIN,d3c7rimkq79yfu.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,d3c7rimkq79yfu.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,linetv.tw,选择代理
  - DOMAIN-SUFFIX,profile.line-scdn.net,选择代理
  - DOMAIN,d349g9zuie06uo.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,channel5.com,选择代理
  - DOMAIN-SUFFIX,my5.tv,选择代理
  - DOMAIN-KEYWORD,nowtv100,选择代理
  - DOMAIN-KEYWORD,rthklive,选择代理
  - DOMAIN,mytvsuperlimited.hb.omtrdc.net,选择代理
  - DOMAIN,mytvsuperlimited.sc.omtrdc.net,选择代理
  - DOMAIN-SUFFIX,mytvsuper.com,选择代理
  - DOMAIN-SUFFIX,tvb.com,选择代理
  - DOMAIN-KEYWORD,apiproxy-device-prod-nlb-,选择代理
  - DOMAIN-KEYWORD,dualstack.apiproxy-,选择代理
  - DOMAIN-KEYWORD,netflixdnstest,选择代理
  - DOMAIN,netflix.com.edgesuite.net,选择代理
  - DOMAIN-SUFFIX,fast.com,选择代理
  - DOMAIN-SUFFIX,netflix.com,选择代理
  - DOMAIN-SUFFIX,netflix.net,选择代理
  - DOMAIN-SUFFIX,netflixdnstest0.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest1.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest2.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest3.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest4.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest5.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest6.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest7.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest8.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest9.com,选择代理
  - DOMAIN-SUFFIX,nflxext.com,选择代理
  - DOMAIN-SUFFIX,nflximg.com,选择代理
  - DOMAIN-SUFFIX,nflximg.net,选择代理
  - DOMAIN-SUFFIX,nflxso.net,选择代理
  - DOMAIN-SUFFIX,nflxvideo.net,选择代理
  - IP-CIDR,8.41.4.0/24,选择代理,no-resolve
  - IP-CIDR,23.246.0.0/18,选择代理,no-resolve
  - IP-CIDR,37.77.184.0/21,选择代理,no-resolve
  - IP-CIDR,38.72.126.0/24,选择代理,no-resolve
  - IP-CIDR,45.57.0.0/17,选择代理,no-resolve
  - IP-CIDR,64.120.128.0/17,选择代理,no-resolve
  - IP-CIDR,66.197.128.0/17,选择代理,no-resolve
  - IP-CIDR,69.53.224.0/19,选择代理,no-resolve
  - IP-CIDR,103.87.204.0/22,选择代理,no-resolve
  - IP-CIDR,108.175.32.0/20,选择代理,no-resolve
  - IP-CIDR,185.2.220.0/22,选择代理,no-resolve
  - IP-CIDR,185.9.188.0/22,选择代理,no-resolve
  - IP-CIDR,192.173.64.0/18,选择代理,no-resolve
  - IP-CIDR,198.38.96.0/19,选择代理,no-resolve
  - IP-CIDR,198.45.48.0/20,选择代理,no-resolve
  - IP-CIDR,203.75.84.0/24,选择代理,no-resolve
  - IP-CIDR,207.45.72.0/22,选择代理,no-resolve
  - IP-CIDR,208.75.76.0/22,选择代理,no-resolve
  - DOMAIN-SUFFIX,dmc.nico,选择代理
  - DOMAIN-SUFFIX,nicovideo.jp,选择代理
  - DOMAIN-SUFFIX,nimg.jp,选择代理
  - DOMAIN-KEYWORD,nivod,选择代理
  - DOMAIN-SUFFIX,biggggg.com,选择代理
  - DOMAIN-SUFFIX,mudvod.tv,选择代理
  - DOMAIN-SUFFIX,nbys.tv,选择代理
  - DOMAIN-SUFFIX,nbys1.tv,选择代理
  - DOMAIN-SUFFIX,nbyy.tv,选择代理
  - DOMAIN-SUFFIX,newpppp.com,选择代理
  - DOMAIN-SUFFIX,nivod.tv,选择代理
  - DOMAIN-SUFFIX,nivodi.tv,选择代理
  - DOMAIN-SUFFIX,nivodz.com,选择代理
  - DOMAIN-SUFFIX,vod360.net,选择代理
  - DOMAIN-KEYWORD,olevod,选择代理
  - DOMAIN-SUFFIX,haiwaikan.com,选择代理
  - DOMAIN-SUFFIX,iole.tv,选择代理
  - DOMAIN-SUFFIX,olehd.com,选择代理
  - DOMAIN-SUFFIX,olelive.com,选择代理
  - DOMAIN-SUFFIX,olevod.com,选择代理
  - DOMAIN-SUFFIX,olevod.io,选择代理
  - DOMAIN-SUFFIX,olevod.tv,选择代理
  - DOMAIN-SUFFIX,olevodtv.com,选择代理
  - DOMAIN-KEYWORD,openai,选择代理
  - DOMAIN-SUFFIX,auth0.com,选择代理
  - DOMAIN-SUFFIX,challenges.cloudflare.com,选择代理
  - DOMAIN-SUFFIX,chatgpt.com,选择代理
  - DOMAIN-SUFFIX,client-api.arkoselabs.com,选择代理
  - DOMAIN-SUFFIX,events.statsigapi.net,选择代理
  - DOMAIN-SUFFIX,featuregates.org,选择代理
  - DOMAIN-SUFFIX,identrust.com,选择代理
  - DOMAIN-SUFFIX,intercom.io,选择代理
  - DOMAIN-SUFFIX,intercomcdn.com,选择代理
  - DOMAIN-SUFFIX,oaistatic.com,选择代理
  - DOMAIN-SUFFIX,oaiusercontent.com,选择代理
  - DOMAIN-SUFFIX,openai.com,选择代理
  - DOMAIN-SUFFIX,openaiapi-site.azureedge.net,选择代理
  - DOMAIN-SUFFIX,sentry.io,选择代理
  - DOMAIN-SUFFIX,stripe.com,选择代理
  - DOMAIN-SUFFIX,pbs.org,选择代理
  - DOMAIN-SUFFIX,pandora.com,选择代理
  - DOMAIN-SUFFIX,phncdn.com,选择代理
  - DOMAIN-SUFFIX,phprcdn.com,选择代理
  - DOMAIN-SUFFIX,pornhub.com,选择代理
  - DOMAIN-SUFFIX,pornhubpremium.com,选择代理
  - DOMAIN-SUFFIX,qobuz.com,选择代理
  - DOMAIN-SUFFIX,p-cdn.us,选择代理
  - DOMAIN-SUFFIX,sndcdn.com,选择代理
  - DOMAIN-SUFFIX,soundcloud.com,选择代理
  - DOMAIN-KEYWORD,-spotify-,选择代理
  - DOMAIN-KEYWORD,spotify.com,选择代理
  - DOMAIN-SUFFIX,pscdn.co,选择代理
  - DOMAIN-SUFFIX,scdn.co,选择代理
  - DOMAIN-SUFFIX,spoti.fi,选择代理
  - DOMAIN-SUFFIX,spotify.com,选择代理
  - DOMAIN-SUFFIX,spotifycdn.com,选择代理
  - DOMAIN-SUFFIX,spotifycdn.net,选择代理
  - DOMAIN-SUFFIX,tidal-cms.s3.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,tidal.com,选择代理
  - DOMAIN-SUFFIX,tidalhifi.com,选择代理
  - DOMAIN,hamifans.emome.net,选择代理
  - DOMAIN-SUFFIX,skyking.com.tw,选择代理
  - DOMAIN-KEYWORD,tiktokcdn,选择代理
  - DOMAIN-SUFFIX,byteoversea.com,选择代理
  - DOMAIN-SUFFIX,ibytedtos.com,选择代理
  - DOMAIN-SUFFIX,ipstatp.com,选择代理
  - DOMAIN-SUFFIX,muscdn.com,选择代理
  - DOMAIN-SUFFIX,musical.ly,选择代理
  - DOMAIN-SUFFIX,tik-tokapi.com,选择代理
  - DOMAIN-SUFFIX,tiktok.com,选择代理
  - DOMAIN-SUFFIX,tiktokcdn.com,选择代理
  - DOMAIN-SUFFIX,tiktokv.com,选择代理
  - DOMAIN-KEYWORD,ttvnw,选择代理
  - DOMAIN-SUFFIX,ext-twitch.tv,选择代理
  - DOMAIN-SUFFIX,jtvnw.net,选择代理
  - DOMAIN-SUFFIX,ttvnw.net,选择代理
  - DOMAIN-SUFFIX,twitch-ext.rootonline.de,选择代理
  - DOMAIN-SUFFIX,twitch.tv,选择代理
  - DOMAIN-SUFFIX,twitchcdn.net,选择代理
  - PROCESS-NAME,com.viu.pad,选择代理
  - PROCESS-NAME,com.viu.phone,选择代理
  - PROCESS-NAME,com.vuclip.viu,选择代理
  - DOMAIN,api.viu.now.com,选择代理
  - DOMAIN,d1k2us671qcoau.cloudfront.net,选择代理
  - DOMAIN,d2anahhhmp1ffz.cloudfront.net,选择代理
  - DOMAIN,dfp6rglgjqszk.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,cognito-identity.us-east-1.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,d1k2us671qcoau.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,d2anahhhmp1ffz.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,dfp6rglgjqszk.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,mobileanalytics.us-east-1.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,viu.com,选择代理
  - DOMAIN-SUFFIX,viu.now.com,选择代理
  - DOMAIN-SUFFIX,viu.tv,选择代理
  - DOMAIN-KEYWORD,youtube,选择代理
  - DOMAIN,youtubei.googleapis.com,选择代理
  - DOMAIN,yt3.ggpht.com,选择代理
  - DOMAIN-SUFFIX,googlevideo.com,选择代理
  - DOMAIN-SUFFIX,gvt2.com,选择代理
  - DOMAIN-SUFFIX,withyoutube.com,选择代理
  - DOMAIN-SUFFIX,youtu.be,选择代理
  - DOMAIN-SUFFIX,youtube-nocookie.com,选择代理
  - DOMAIN-SUFFIX,youtube.com,选择代理
  - DOMAIN-SUFFIX,youtubeeducation.com,选择代理
  - DOMAIN-SUFFIX,youtubegaming.com,选择代理
  - DOMAIN-SUFFIX,youtubekids.com,选择代理
  - DOMAIN-SUFFIX,yt.be,选择代理
  - DOMAIN-SUFFIX,ytimg.com,选择代理
  - DOMAIN,music.youtube.com,选择代理
  - DOMAIN-SUFFIX,1password.com,选择代理
  - DOMAIN-SUFFIX,adguard.org,选择代理
  - DOMAIN-SUFFIX,bit.no.com,选择代理
  - DOMAIN-SUFFIX,btlibrary.me,选择代理
  - DOMAIN-SUFFIX,cloudcone.com,选择代理
  - DOMAIN-SUFFIX,dubox.com,选择代理
  - DOMAIN-SUFFIX,gameloft.com,选择代理
  - DOMAIN-SUFFIX,garena.com,选择代理
  - DOMAIN-SUFFIX,hoyolab.com,选择代理
  - DOMAIN-SUFFIX,inoreader.com,选择代理
  - DOMAIN-SUFFIX,ip138.com,选择代理
  - DOMAIN-SUFFIX,linkedin.com,选择代理
  - DOMAIN-SUFFIX,myteamspeak.com,选择代理
  - DOMAIN-SUFFIX,notion.so,选择代理
  - DOMAIN-SUFFIX,ping.pe,选择代理
  - DOMAIN-SUFFIX,reddit.com,选择代理
  - DOMAIN-SUFFIX,teddysun.com,选择代理
  - DOMAIN-SUFFIX,tumbex.com,选择代理
  - DOMAIN-SUFFIX,twdvd.com,选择代理
  - DOMAIN-SUFFIX,unsplash.com,选择代理
  - DOMAIN-SUFFIX,buzzsprout.com,选择代理
  - DOMAIN-SUFFIX,eu,选择代理
  - DOMAIN-SUFFIX,hk,选择代理
  - DOMAIN-SUFFIX,jp,选择代理
  - DOMAIN-SUFFIX,kr,选择代理
  - DOMAIN-SUFFIX,sg,选择代理
  - DOMAIN-SUFFIX,tw,选择代理
  - DOMAIN-SUFFIX,uk,选择代理
  - DOMAIN-KEYWORD,1e100,选择代理
  - DOMAIN-KEYWORD,abema,选择代理
  - DOMAIN-KEYWORD,appledaily,选择代理
  - DOMAIN-KEYWORD,avtb,选择代理
  - DOMAIN-KEYWORD,beetalk,选择代理
  - DOMAIN-KEYWORD,blogspot,选择代理
  - DOMAIN-KEYWORD,dropbox,选择代理
  - DOMAIN-KEYWORD,facebook,选择代理
  - DOMAIN-KEYWORD,fbcdn,选择代理
  - DOMAIN-KEYWORD,github,选择代理
  - DOMAIN-KEYWORD,gmail,选择代理
  - DOMAIN-KEYWORD,google,选择代理
  - DOMAIN-KEYWORD,instagram,选择代理
  - DOMAIN-KEYWORD,porn,选择代理
  - DOMAIN-KEYWORD,sci-hub,选择代理
  - DOMAIN-KEYWORD,spotify,选择代理
  - DOMAIN-KEYWORD,telegram,选择代理
  - DOMAIN-KEYWORD,twitter,选择代理
  - DOMAIN-KEYWORD,whatsapp,选择代理
  - DOMAIN-KEYWORD,youtube,选择代理
  - DOMAIN-SUFFIX,4sqi.net,选择代理
  - DOMAIN-SUFFIX,a248.e.akamai.net,选择代理
  - DOMAIN-SUFFIX,adobedtm.com,选择代理
  - DOMAIN-SUFFIX,ampproject.org,选择代理
  - DOMAIN-SUFFIX,android.com,选择代理
  - DOMAIN-SUFFIX,aolcdn.com,选择代理
  - DOMAIN-SUFFIX,apkmirror.com,选择代理
  - DOMAIN-SUFFIX,apkpure.com,选择代理
  - DOMAIN-SUFFIX,app-measurement.com,选择代理
  - DOMAIN-SUFFIX,appspot.com,选择代理
  - DOMAIN-SUFFIX,archive.org,选择代理
  - DOMAIN-SUFFIX,armorgames.com,选择代理
  - DOMAIN-SUFFIX,aspnetcdn.com,选择代理
  - DOMAIN-SUFFIX,awsstatic.com,选择代理
  - DOMAIN-SUFFIX,azureedge.net,选择代理
  - DOMAIN-SUFFIX,azurewebsites.net,选择代理
  - DOMAIN-SUFFIX,bandwagonhost.com,选择代理
  - DOMAIN-SUFFIX,bing.com,选择代理
  - DOMAIN-SUFFIX,bkrtx.com,选择代理
  - DOMAIN-SUFFIX,blogcdn.com,选择代理
  - DOMAIN-SUFFIX,blogger.com,选择代理
  - DOMAIN-SUFFIX,blogsmithmedia.com,选择代理
  - DOMAIN-SUFFIX,blogspot.com,选择代理
  - DOMAIN-SUFFIX,blogspot.hk,选择代理
  - DOMAIN-SUFFIX,blogspot.jp,选择代理
  - DOMAIN-SUFFIX,bloomberg.cn,选择代理
  - DOMAIN-SUFFIX,bloomberg.com,选择代理
  - DOMAIN-SUFFIX,box.com,选择代理
  - DOMAIN-SUFFIX,cachefly.net,选择代理
  - DOMAIN-SUFFIX,cdnst.net,选择代理
  - DOMAIN-SUFFIX,cloudfront.net,选择代理
  - DOMAIN-SUFFIX,comodoca.com,选择代理
  - DOMAIN-SUFFIX,daum.net,选择代理
  - DOMAIN-SUFFIX,deskconnect.com,选择代理
  - DOMAIN-SUFFIX,disqus.com,选择代理
  - DOMAIN-SUFFIX,disquscdn.com,选择代理
  - DOMAIN-SUFFIX,dropbox.com,选择代理
  - DOMAIN-SUFFIX,dropboxapi.com,选择代理
  - DOMAIN-SUFFIX,dropboxstatic.com,选择代理
  - DOMAIN-SUFFIX,dropboxusercontent.com,选择代理
  - DOMAIN-SUFFIX,duckduckgo.com,选择代理
  - DOMAIN-SUFFIX,edgecastcdn.net,选择代理
  - DOMAIN-SUFFIX,edgekey.net,选择代理
  - DOMAIN-SUFFIX,edgesuite.net,选择代理
  - DOMAIN-SUFFIX,eurekavpt.com,选择代理
  - DOMAIN-SUFFIX,fastmail.com,选择代理
  - DOMAIN-SUFFIX,firebaseio.com,选择代理
  - DOMAIN-SUFFIX,flickr.com,选择代理
  - DOMAIN-SUFFIX,flipboard.com,选择代理
  - DOMAIN-SUFFIX,gfx.ms,选择代理
  - DOMAIN-SUFFIX,gongm.in,选择代理
  - DOMAIN-SUFFIX,hulu.com,选择代理
  - DOMAIN-SUFFIX,id.heroku.com,选择代理
  - DOMAIN-SUFFIX,io.io,选择代理
  - DOMAIN-SUFFIX,issuu.com,选择代理
  - DOMAIN-SUFFIX,ixquick.com,选择代理
  - DOMAIN-SUFFIX,jtvnw.net,选择代理
  - DOMAIN-SUFFIX,kat.cr,选择代理
  - DOMAIN-SUFFIX,kik.com,选择代理
  - DOMAIN-SUFFIX,kobo.com,选择代理
  - DOMAIN-SUFFIX,kobobooks.com,选择代理
  - DOMAIN-SUFFIX,licdn.com,选择代理
  - DOMAIN-SUFFIX,live.net,选择代理
  - DOMAIN-SUFFIX,livefilestore.com,选择代理
  - DOMAIN-SUFFIX,llnwd.net,选择代理
  - DOMAIN-SUFFIX,macrumors.com,选择代理
  - DOMAIN-SUFFIX,medium.com,选择代理
  - DOMAIN-SUFFIX,mega.nz,选择代理
  - DOMAIN-SUFFIX,megaupload.com,选择代理
  - DOMAIN-SUFFIX,messenger.com,选择代理
  - DOMAIN-SUFFIX,netdna-cdn.com,选择代理
  - DOMAIN-SUFFIX,nintendo.net,选择代理
  - DOMAIN-SUFFIX,nsstatic.net,选择代理
  - DOMAIN-SUFFIX,nytstyle.com,选择代理
  - DOMAIN-SUFFIX,overcast.fm,选择代理
  - DOMAIN-SUFFIX,openvpn.net,选择代理
  - DOMAIN-SUFFIX,periscope.tv,选择代理
  - DOMAIN-SUFFIX,pinimg.com,选择代理
  - DOMAIN-SUFFIX,pinterest.com,选择代理
  - DOMAIN-SUFFIX,potato.im,选择代理
  - DOMAIN-SUFFIX,prfct.co,选择代理
  - DOMAIN-SUFFIX,pscp.tv,选择代理
  - DOMAIN-SUFFIX,quora.com,选择代理
  - DOMAIN-SUFFIX,resilio.com,选择代理
  - DOMAIN-SUFFIX,sfx.ms,选择代理
  - DOMAIN-SUFFIX,shadowsocks.org,选择代理
  - DOMAIN-SUFFIX,slack-edge.com,选择代理
  - DOMAIN-SUFFIX,smartdnsproxy.com,选择代理
  - DOMAIN-SUFFIX,sndcdn.com,选择代理
  - DOMAIN-SUFFIX,soundcloud.com,选择代理
  - DOMAIN-SUFFIX,startpage.com,选择代理
  - DOMAIN-SUFFIX,staticflickr.com,选择代理
  - DOMAIN-SUFFIX,symauth.com,选择代理
  - DOMAIN-SUFFIX,symcb.com,选择代理
  - DOMAIN-SUFFIX,symcd.com,选择代理
  - DOMAIN-SUFFIX,textnow.com,选择代理
  - DOMAIN-SUFFIX,textnow.me,选择代理
  - DOMAIN-SUFFIX,thefacebook.com,选择代理
  - DOMAIN-SUFFIX,thepiratebay.org,选择代理
  - DOMAIN-SUFFIX,torproject.org,选择代理
  - DOMAIN-SUFFIX,trustasiassl.com,选择代理
  - DOMAIN-SUFFIX,tumblr.co,选择代理
  - DOMAIN-SUFFIX,tumblr.com,选择代理
  - DOMAIN-SUFFIX,tvb.com,选择代理
  - DOMAIN-SUFFIX,txmblr.com,选择代理
  - DOMAIN-SUFFIX,v2ex.com,选择代理
  - DOMAIN-SUFFIX,vimeo.com,选择代理
  - DOMAIN-SUFFIX,vine.co,选择代理
  - DOMAIN-SUFFIX,vox-cdn.com,选择代理
  - DOMAIN-SUFFIX,amazon.co.jp,选择代理
  - DOMAIN-SUFFIX,amazon.com,选择代理
  - DOMAIN-SUFFIX,amazonaws.com,选择代理
  - IP-CIDR,13.32.0.0/15,选择代理,no-resolve
  - IP-CIDR,13.35.0.0/17,选择代理,no-resolve
  - IP-CIDR,18.184.0.0/15,选择代理,no-resolve
  - IP-CIDR,18.194.0.0/15,选择代理,no-resolve
  - IP-CIDR,18.208.0.0/13,选择代理,no-resolve
  - IP-CIDR,18.232.0.0/14,选择代理,no-resolve
  - IP-CIDR,52.58.0.0/15,选择代理,no-resolve
  - IP-CIDR,52.74.0.0/16,选择代理,no-resolve
  - IP-CIDR,52.77.0.0/16,选择代理,no-resolve
  - IP-CIDR,52.84.0.0/15,选择代理,no-resolve
  - IP-CIDR,52.200.0.0/13,选择代理,no-resolve
  - IP-CIDR,54.93.0.0/16,选择代理,no-resolve
  - IP-CIDR,54.156.0.0/14,选择代理,no-resolve
  - IP-CIDR,54.226.0.0/15,选择代理,no-resolve
  - IP-CIDR,54.230.156.0/22,选择代理,no-resolve
  - DOMAIN-KEYWORD,uk-live,选择代理
  - DOMAIN-SUFFIX,bbc.co,选择代理
  - DOMAIN-SUFFIX,bbc.com,选择代理
  - DOMAIN-SUFFIX,claude.ai,选择代理
  - DOMAIN-SUFFIX,anthropic.com,选择代理
  - DOMAIN-SUFFIX,apache.org,选择代理
  - DOMAIN-SUFFIX,docker.com,选择代理
  - DOMAIN-SUFFIX,docker.io,选择代理
  - DOMAIN-SUFFIX,elastic.co,选择代理
  - DOMAIN-SUFFIX,elastic.com,选择代理
  - DOMAIN-SUFFIX,gcr.io,选择代理
  - DOMAIN-SUFFIX,gitlab.com,选择代理
  - DOMAIN-SUFFIX,gitlab.io,选择代理
  - DOMAIN-SUFFIX,jitpack.io,选择代理
  - DOMAIN-SUFFIX,maven.org,选择代理
  - DOMAIN-SUFFIX,medium.com,选择代理
  - DOMAIN-SUFFIX,mvnrepository.com,选择代理
  - DOMAIN-SUFFIX,quay.io,选择代理
  - DOMAIN-SUFFIX,reddit.com,选择代理
  - DOMAIN-SUFFIX,redhat.com,选择代理
  - DOMAIN-SUFFIX,sonatype.org,选择代理
  - DOMAIN-SUFFIX,sourcegraph.com,选择代理
  - DOMAIN-SUFFIX,spring.io,选择代理
  - DOMAIN-SUFFIX,spring.net,选择代理
  - DOMAIN-SUFFIX,stackoverflow.com,选择代理
  - DOMAIN,d1q6f0aelx0por.cloudfront.net,选择代理
  - DOMAIN,d2wy8f7a9ursnm.cloudfront.net,选择代理
  - DOMAIN,d36jcksde1wxzq.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,compose-spec.io,选择代理
  - DOMAIN-SUFFIX,docker.com,选择代理
  - DOMAIN-SUFFIX,docker.io,选择代理
  - DOMAIN-SUFFIX,dockerhub.com,选择代理
  - DOMAIN-SUFFIX,discord.co,选择代理
  - DOMAIN-SUFFIX,discord.com,选择代理
  - DOMAIN-SUFFIX,discord.gg,选择代理
  - DOMAIN-SUFFIX,discord.media,选择代理
  - DOMAIN-SUFFIX,discordapp.com,选择代理
  - DOMAIN-SUFFIX,discordapp.net,选择代理
  - DOMAIN-SUFFIX,facebook.com,选择代理
  - DOMAIN-SUFFIX,fb.com,选择代理
  - DOMAIN-SUFFIX,fb.me,选择代理
  - DOMAIN-SUFFIX,fbcdn.com,选择代理
  - DOMAIN-SUFFIX,fbcdn.net,选择代理
  - IP-CIDR,31.13.24.0/21,选择代理,no-resolve
  - IP-CIDR,31.13.64.0/18,选择代理,no-resolve
  - IP-CIDR,45.64.40.0/22,选择代理,no-resolve
  - IP-CIDR,66.220.144.0/20,选择代理,no-resolve
  - IP-CIDR,69.63.176.0/20,选择代理,no-resolve
  - IP-CIDR,69.171.224.0/19,选择代理,no-resolve
  - IP-CIDR,74.119.76.0/22,选择代理,no-resolve
  - IP-CIDR,103.4.96.0/22,选择代理,no-resolve
  - IP-CIDR,129.134.0.0/17,选择代理,no-resolve
  - IP-CIDR,157.240.0.0/17,选择代理,no-resolve
  - IP-CIDR,173.252.64.0/18,选择代理,no-resolve
  - IP-CIDR,179.60.192.0/22,选择代理,no-resolve
  - IP-CIDR,185.60.216.0/22,选择代理,no-resolve
  - IP-CIDR,204.15.20.0/22,选择代理,no-resolve
  - DOMAIN-SUFFIX,github.com,选择代理
  - DOMAIN-SUFFIX,github.io,选择代理
  - DOMAIN-SUFFIX,githubapp.com,选择代理
  - DOMAIN-SUFFIX,githubassets.com,选择代理
  - DOMAIN-SUFFIX,githubusercontent.com,选择代理
  - DOMAIN-SUFFIX,1e100.net,选择代理
  - DOMAIN-SUFFIX,2mdn.net,选择代理
  - DOMAIN-SUFFIX,app-measurement.net,选择代理
  - DOMAIN-SUFFIX,g.co,选择代理
  - DOMAIN-SUFFIX,ggpht.com,选择代理
  - DOMAIN-SUFFIX,goo.gl,选择代理
  - DOMAIN-SUFFIX,googleapis.cn,选择代理
  - DOMAIN-SUFFIX,googleapis.com,选择代理
  - DOMAIN-SUFFIX,gstatic.cn,选择代理
  - DOMAIN-SUFFIX,gstatic.com,选择代理
  - DOMAIN-SUFFIX,gvt0.com,选择代理
  - DOMAIN-SUFFIX,gvt1.com,选择代理
  - DOMAIN-SUFFIX,gvt2.com,选择代理
  - DOMAIN-SUFFIX,gvt3.com,选择代理
  - DOMAIN-SUFFIX,xn--ngstr-lra8j.com,选择代理
  - DOMAIN-SUFFIX,youtu.be,选择代理
  - DOMAIN-SUFFIX,youtube-nocookie.com,选择代理
  - DOMAIN-SUFFIX,youtube.com,选择代理
  - DOMAIN-SUFFIX,yt.be,选择代理
  - DOMAIN-SUFFIX,ytimg.com,选择代理
  - IP-CIDR,74.125.0.0/16,选择代理,no-resolve
  - IP-CIDR,173.194.0.0/16,选择代理,no-resolve
  - IP-CIDR,120.232.181.162/32,选择代理,no-resolve
  - IP-CIDR,120.241.147.226/32,选择代理,no-resolve
  - IP-CIDR,120.253.253.226/32,选择代理,no-resolve
  - IP-CIDR,120.253.255.162/32,选择代理,no-resolve
  - IP-CIDR,120.253.255.34/32,选择代理,no-resolve
  - IP-CIDR,120.253.255.98/32,选择代理,no-resolve
  - IP-CIDR,180.163.150.162/32,选择代理,no-resolve
  - IP-CIDR,180.163.150.34/32,选择代理,no-resolve
  - IP-CIDR,180.163.151.162/32,选择代理,no-resolve
  - IP-CIDR,180.163.151.34/32,选择代理,no-resolve
  - IP-CIDR,203.208.39.0/24,选择代理,no-resolve
  - IP-CIDR,203.208.40.0/24,选择代理,no-resolve
  - IP-CIDR,203.208.41.0/24,选择代理,no-resolve
  - IP-CIDR,203.208.43.0/24,选择代理,no-resolve
  - IP-CIDR,203.208.50.0/24,选择代理,no-resolve
  - IP-CIDR,220.181.174.162/32,选择代理,no-resolve
  - IP-CIDR,220.181.174.226/32,选择代理,no-resolve
  - IP-CIDR,220.181.174.34/32,选择代理,no-resolve
  - DOMAIN-SUFFIX,cdninstagram.com,选择代理
  - DOMAIN-SUFFIX,instagram.com,选择代理
  - DOMAIN-SUFFIX,instagr.am,选择代理
  - DOMAIN-SUFFIX,iwara.tv,选择代理
  - DOMAIN-SUFFIX,kakao.com,选择代理
  - DOMAIN-SUFFIX,kakao.co.kr,选择代理
  - DOMAIN-SUFFIX,kakaocdn.net,选择代理
  - IP-CIDR,1.201.0.0/24,选择代理,no-resolve
  - IP-CIDR,27.0.236.0/22,选择代理,no-resolve
  - IP-CIDR,103.27.148.0/22,选择代理,no-resolve
  - IP-CIDR,103.246.56.0/22,选择代理,no-resolve
  - IP-CIDR,110.76.140.0/22,选择代理,no-resolve
  - IP-CIDR,113.61.104.0/22,选择代理,no-resolve
  - DOMAIN-SUFFIX,lin.ee,选择代理
  - DOMAIN-SUFFIX,line-apps.com,选择代理
  - DOMAIN-SUFFIX,line-cdn.net,选择代理
  - DOMAIN-SUFFIX,line-scdn.net,选择代理
  - DOMAIN-SUFFIX,line.me,选择代理
  - DOMAIN-SUFFIX,line.naver.jp,选择代理
  - DOMAIN-SUFFIX,nhncorp.jp,选择代理
  - IP-CIDR,103.2.28.0/24,选择代理,no-resolve
  - IP-CIDR,103.2.30.0/23,选择代理,no-resolve
  - IP-CIDR,119.235.224.0/24,选择代理,no-resolve
  - IP-CIDR,119.235.232.0/24,选择代理,no-resolve
  - IP-CIDR,119.235.235.0/24,选择代理,no-resolve
  - IP-CIDR,119.235.236.0/23,选择代理,no-resolve
  - IP-CIDR,147.92.128.0/17,选择代理,no-resolve
  - IP-CIDR,203.104.128.0/19,选择代理,no-resolve
  - DOMAIN-SUFFIX,openai.com,选择代理
  - DOMAIN-SUFFIX,challenges.cloudflare.com,选择代理
  - DOMAIN-KEYWORD,1drv,选择代理
  - DOMAIN-KEYWORD,onedrive,选择代理
  - DOMAIN-KEYWORD,skydrive,选择代理
  - DOMAIN-SUFFIX,livefilestore.com,选择代理
  - DOMAIN-SUFFIX,oneclient.sfx.ms,选择代理
  - DOMAIN-SUFFIX,onedrive.com,选择代理
  - DOMAIN-SUFFIX,onedrive.live.com,选择代理
  - DOMAIN-SUFFIX,photos.live.com,选择代理
  - DOMAIN-SUFFIX,skydrive.wns.windows.com,选择代理
  - DOMAIN-SUFFIX,spoprod-a.akamaihd.net,选择代理
  - DOMAIN-SUFFIX,storage.live.com,选择代理
  - DOMAIN-SUFFIX,storage.msn.com,选择代理
  - DOMAIN-KEYWORD,porn,选择代理
  - DOMAIN-SUFFIX,8teenxxx.com,选择代理
  - DOMAIN-SUFFIX,ahcdn.com,选择代理
  - DOMAIN-SUFFIX,bcvcdn.com,选择代理
  - DOMAIN-SUFFIX,bongacams.com,选择代理
  - DOMAIN-SUFFIX,chaturbate.com,选择代理
  - DOMAIN-SUFFIX,dditscdn.com,选择代理
  - DOMAIN-SUFFIX,livejasmin.com,选择代理
  - DOMAIN-SUFFIX,phncdn.com,选择代理
  - DOMAIN-SUFFIX,phprcdn.com,选择代理
  - DOMAIN-SUFFIX,pornhub.com,选择代理
  - DOMAIN-SUFFIX,pornhubpremium.com,选择代理
  - DOMAIN-SUFFIX,rdtcdn.com,选择代理
  - DOMAIN-SUFFIX,redtube.com,选择代理
  - DOMAIN-SUFFIX,sb-cd.com,选择代理
  - DOMAIN-SUFFIX,spankbang.com,选择代理
  - DOMAIN-SUFFIX,t66y.com,选择代理
  - DOMAIN-SUFFIX,xhamster.com,选择代理
  - DOMAIN-SUFFIX,xnxx-cdn.com,选择代理
  - DOMAIN-SUFFIX,xnxx.com,选择代理
  - DOMAIN-SUFFIX,xvideos-cdn.com,选择代理
  - DOMAIN-SUFFIX,xvideos.com,选择代理
  - DOMAIN-SUFFIX,ypncdn.com,选择代理
  - DOMAIN-SUFFIX,pixiv.net,选择代理
  - DOMAIN-SUFFIX,pximg.net,选择代理
  - DOMAIN-SUFFIX,fanbox.cc,选择代理
  - DOMAIN-SUFFIX,amplitude.com,选择代理
  - DOMAIN-SUFFIX,firebaseio.com,选择代理
  - DOMAIN-SUFFIX,hockeyapp.net,选择代理
  - DOMAIN-SUFFIX,readdle.com,选择代理
  - DOMAIN-SUFFIX,smartmailcloud.com,选择代理
  - DOMAIN-SUFFIX,fanatical.com,选择代理
  - DOMAIN-SUFFIX,humblebundle.com,选择代理
  - DOMAIN-SUFFIX,underlords.com,选择代理
  - DOMAIN-SUFFIX,valvesoftware.com,选择代理
  - DOMAIN-SUFFIX,playartifact.com,选择代理
  - DOMAIN-SUFFIX,steam-chat.com,选择代理
  - DOMAIN-SUFFIX,steamcommunity.com,选择代理
  - DOMAIN-SUFFIX,steamgames.com,选择代理
  - DOMAIN-SUFFIX,steampowered.com,选择代理
  - DOMAIN-SUFFIX,steamserver.net,选择代理
  - DOMAIN-SUFFIX,steamstatic.com,选择代理
  - DOMAIN-SUFFIX,steamstat.us,选择代理
  - DOMAIN,steambroadcast.akamaized.net,选择代理
  - DOMAIN,steamcommunity-a.akamaihd.net,选择代理
  - DOMAIN,steamstore-a.akamaihd.net,选择代理
  - DOMAIN,steamusercontent-a.akamaihd.net,选择代理
  - DOMAIN,steamuserimages-a.akamaihd.net,选择代理
  - DOMAIN,steampipe.akamaized.net,选择代理
  - DOMAIN-SUFFIX,tap.io,选择代理
  - DOMAIN-SUFFIX,taptap.tw,选择代理
  - DOMAIN-SUFFIX,twitch.tv,选择代理
  - DOMAIN-SUFFIX,ttvnw.net,选择代理
  - DOMAIN-SUFFIX,jtvnw.net,选择代理
  - DOMAIN-KEYWORD,ttvnw,选择代理
  - DOMAIN-SUFFIX,t.co,选择代理
  - DOMAIN-SUFFIX,twimg.co,选择代理
  - DOMAIN-SUFFIX,twimg.com,选择代理
  - DOMAIN-SUFFIX,twimg.org,选择代理
  - DOMAIN-SUFFIX,x.com,选择代理
  - DOMAIN-SUFFIX,t.me,选择代理
  - DOMAIN-SUFFIX,tdesktop.com,选择代理
  - DOMAIN-SUFFIX,telegra.ph,选择代理
  - DOMAIN-SUFFIX,telegram.me,选择代理
  - DOMAIN-SUFFIX,telegram.org,选择代理
  - DOMAIN-SUFFIX,telesco.pe,选择代理
  - IP-CIDR,91.108.0.0/16,选择代理,no-resolve
  - IP-CIDR,109.239.140.0/24,选择代理,no-resolve
  - IP-CIDR,149.154.160.0/20,选择代理,no-resolve
  - IP-CIDR6,2001:67c:4e8::/48,选择代理,no-resolve
  - IP-CIDR6,2001:b28:f23d::/48,选择代理,no-resolve
  - IP-CIDR6,2001:b28:f23f::/48,选择代理,no-resolve
  - DOMAIN-SUFFIX,terabox.com,选择代理
  - DOMAIN-SUFFIX,teraboxcdn.com,选择代理
  - IP-CIDR,18.194.0.0/15,选择代理,no-resolve
  - IP-CIDR,34.224.0.0/12,选择代理,no-resolve
  - IP-CIDR,54.242.0.0/15,选择代理,no-resolve
  - IP-CIDR,50.22.198.204/30,选择代理,no-resolve
  - IP-CIDR,208.43.122.128/27,选择代理,no-resolve
  - IP-CIDR,108.168.174.0/16,选择代理,no-resolve
  - IP-CIDR,173.192.231.32/27,选择代理,no-resolve
  - IP-CIDR,158.85.5.192/27,选择代理,no-resolve
  - IP-CIDR,174.37.243.0/16,选择代理,no-resolve
  - IP-CIDR,158.85.46.128/27,选择代理,no-resolve
  - IP-CIDR,173.192.222.160/27,选择代理,no-resolve
  - IP-CIDR,184.173.128.0/17,选择代理,no-resolve
  - IP-CIDR,158.85.224.160/27,选择代理,no-resolve
  - IP-CIDR,75.126.150.0/16,选择代理,no-resolve
  - IP-CIDR,69.171.235.0/16,选择代理,no-resolve
  - DOMAIN-SUFFIX,mediawiki.org,选择代理
  - DOMAIN-SUFFIX,wikibooks.org,选择代理
  - DOMAIN-SUFFIX,wikidata.org,选择代理
  - DOMAIN-SUFFIX,wikileaks.org,选择代理
  - DOMAIN-SUFFIX,wikimedia.org,选择代理
  - DOMAIN-SUFFIX,wikinews.org,选择代理
  - DOMAIN-SUFFIX,wikipedia.org,选择代理
  - DOMAIN-SUFFIX,wikiquote.org,选择代理
  - DOMAIN-SUFFIX,wikisource.org,选择代理
  - DOMAIN-SUFFIX,wikiversity.org,选择代理
  - DOMAIN-SUFFIX,wikivoyage.org,选择代理
  - DOMAIN-SUFFIX,wiktionary.org,选择代理
  - DOMAIN-SUFFIX,zoom.us,选择代理
  - DOMAIN-SUFFIX,zoomgov.com,选择代理
  - DOMAIN-SUFFIX,neulion.com,选择代理
  - DOMAIN-SUFFIX,icntv.xyz,选择代理
  - DOMAIN-SUFFIX,flzbcdn.xyz,选择代理
  - DOMAIN-SUFFIX,ocnttv.com,选择代理
  - DOMAIN-SUFFIX,vikacg.com,选择代理
  - DOMAIN-SUFFIX,picjs.xyz,选择代理
  - DOMAIN-SUFFIX,13th.tech,选择代理
  - DOMAIN-SUFFIX,423down.com,选择代理
  - DOMAIN-SUFFIX,bokecc.com,选择代理
  - DOMAIN-SUFFIX,chaipip.com,选择代理
  - DOMAIN-SUFFIX,chinaplay.store,选择代理
  - DOMAIN-SUFFIX,hrtsea.com,选择代理
  - DOMAIN-SUFFIX,kaikeba.com,选择代理
  - DOMAIN-SUFFIX,laomo.me,选择代理
  - DOMAIN-SUFFIX,mpyit.com,选择代理
  - DOMAIN-SUFFIX,msftconnecttest.com,选择代理
  - DOMAIN-SUFFIX,msftncsi.com,选择代理
  - DOMAIN-SUFFIX,qupu123.com,选择代理
  - DOMAIN-SUFFIX,pdfwifi.com,选择代理
  - DOMAIN-SUFFIX,zhenguanyu.biz,选择代理
  - DOMAIN-SUFFIX,zhenguanyu.com,选择代理
  - DOMAIN-SUFFIX,snapdrop.net,选择代理
  - DOMAIN-SUFFIX,tebex.io,选择代理
  - DOMAIN-SUFFIX,cn,选择代理
  - DOMAIN-SUFFIX,xn--fiqs8s,选择代理
  - DOMAIN-SUFFIX,xn--55qx5d,选择代理
  - DOMAIN-SUFFIX,xn--io0a7i,选择代理
  - DOMAIN-KEYWORD,360buy,选择代理
  - DOMAIN-KEYWORD,alicdn,选择代理
  - DOMAIN-KEYWORD,alimama,选择代理
  - DOMAIN-KEYWORD,alipay,选择代理
  - DOMAIN-KEYWORD,appzapp,选择代理
  - DOMAIN-KEYWORD,baidupcs,选择代理
  - DOMAIN-KEYWORD,bilibili,选择代理
  - DOMAIN-KEYWORD,ccgslb,选择代理
  - DOMAIN-KEYWORD,chinacache,选择代理
  - DOMAIN-KEYWORD,duobao,选择代理
  - DOMAIN-KEYWORD,jdpay,选择代理
  - DOMAIN-KEYWORD,moke,选择代理
  - DOMAIN-KEYWORD,qhimg,选择代理
  - DOMAIN-KEYWORD,vpimg,选择代理
  - DOMAIN-KEYWORD,xiami,选择代理
  - DOMAIN-KEYWORD,xiaomi,选择代理
  - DOMAIN-SUFFIX,360.com,选择代理
  - DOMAIN-SUFFIX,360kuai.com,选择代理
  - DOMAIN-SUFFIX,360safe.com,选择代理
  - DOMAIN-SUFFIX,dhrest.com,选择代理
  - DOMAIN-SUFFIX,qhres.com,选择代理
  - DOMAIN-SUFFIX,qhstatic.com,选择代理
  - DOMAIN-SUFFIX,qhupdate.com,选择代理
  - DOMAIN-SUFFIX,so.com,选择代理
  - DOMAIN-SUFFIX,4399.com,选择代理
  - DOMAIN-SUFFIX,4399pk.com,选择代理
  - DOMAIN-SUFFIX,5054399.com,选择代理
  - DOMAIN-SUFFIX,img4399.com,选择代理
  - DOMAIN-SUFFIX,58.com,选择代理
  - DOMAIN-SUFFIX,1688.com,选择代理
  - DOMAIN-SUFFIX,aliapp.org,选择代理
  - DOMAIN-SUFFIX,alibaba.com,选择代理
  - DOMAIN-SUFFIX,alibabacloud.com,选择代理
  - DOMAIN-SUFFIX,alibabausercontent.com,选择代理
  - DOMAIN-SUFFIX,alicdn.com,选择代理
  - DOMAIN-SUFFIX,alicloudccp.com,选择代理
  - DOMAIN-SUFFIX,aliexpress.com,选择代理
  - DOMAIN-SUFFIX,aliimg.com,选择代理
  - DOMAIN-SUFFIX,alikunlun.com,选择代理
  - DOMAIN-SUFFIX,alipay.com,选择代理
  - DOMAIN-SUFFIX,alipayobjects.com,选择代理
  - DOMAIN-SUFFIX,alisoft.com,选择代理
  - DOMAIN-SUFFIX,aliyun.com,选择代理
  - DOMAIN-SUFFIX,aliyuncdn.com,选择代理
  - DOMAIN-SUFFIX,aliyuncs.com,选择代理
  - DOMAIN-SUFFIX,aliyundrive.com,选择代理
  - DOMAIN-SUFFIX,aliyundrive.net,选择代理
  - DOMAIN-SUFFIX,amap.com,选择代理
  - DOMAIN-SUFFIX,autonavi.com,选择代理
  - DOMAIN-SUFFIX,dingtalk.com,选择代理
  - DOMAIN-SUFFIX,ele.me,选择代理
  - DOMAIN-SUFFIX,hichina.com,选择代理
  - DOMAIN-SUFFIX,mmstat.com,选择代理
  - DOMAIN-SUFFIX,mxhichina.com,选择代理
  - DOMAIN-SUFFIX,soku.com,选择代理
  - DOMAIN-SUFFIX,taobao.com,选择代理
  - DOMAIN-SUFFIX,taobaocdn.com,选择代理
  - DOMAIN-SUFFIX,tbcache.com,选择代理
  - DOMAIN-SUFFIX,tbcdn.com,选择代理
  - DOMAIN-SUFFIX,tmall.com,选择代理
  - DOMAIN-SUFFIX,tmall.hk,选择代理
  - DOMAIN-SUFFIX,ucweb.com,选择代理
  - DOMAIN-SUFFIX,xiami.com,选择代理
  - DOMAIN-SUFFIX,xiami.net,选择代理
  - DOMAIN-SUFFIX,ykimg.com,选择代理
  - DOMAIN-SUFFIX,youku.com,选择代理
  - DOMAIN-SUFFIX,baidu.com,选择代理
  - DOMAIN-SUFFIX,baidubcr.com,选择代理
  - DOMAIN-SUFFIX,baidupcs.com,选择代理
  - DOMAIN-SUFFIX,baidustatic.com,选择代理
  - DOMAIN-SUFFIX,bcebos.com,选择代理
  - DOMAIN-SUFFIX,bdimg.com,选择代理
  - DOMAIN-SUFFIX,bdstatic.com,选择代理
  - DOMAIN-SUFFIX,bdurl.net,选择代理
  - DOMAIN-SUFFIX,hao123.com,选择代理
  - DOMAIN-SUFFIX,hao123img.com,选择代理
  - DOMAIN-SUFFIX,jomodns.com,选择代理
  - DOMAIN-SUFFIX,yunjiasu-cdn.net,选择代理
  - DOMAIN-SUFFIX,acg.tv,选择代理
  - DOMAIN-SUFFIX,acgvideo.com,选择代理
  - DOMAIN-SUFFIX,b23.tv,选择代理
  - DOMAIN-SUFFIX,bigfun.cn,选择代理
  - DOMAIN-SUFFIX,bigfunapp.cn,选择代理
  - DOMAIN-SUFFIX,biliapi.com,选择代理
  - DOMAIN-SUFFIX,biliapi.net,选择代理
  - DOMAIN-SUFFIX,bilibili.com,选择代理
  - DOMAIN-SUFFIX,bilibili.co,选择代理
  - DOMAIN-SUFFIX,biliintl.co,选择代理
  - DOMAIN-SUFFIX,biligame.com,选择代理
  - DOMAIN-SUFFIX,biligame.net,选择代理
  - DOMAIN-SUFFIX,bilivideo.com,选择代理
  - DOMAIN-SUFFIX,bilivideo.cn,选择代理
  - DOMAIN-SUFFIX,hdslb.com,选择代理
  - DOMAIN-SUFFIX,im9.com,选择代理
  - DOMAIN-SUFFIX,smtcdns.net,选择代理
  - DOMAIN-SUFFIX,amemv.com,选择代理
  - DOMAIN-SUFFIX,bdxiguaimg.com,选择代理
  - DOMAIN-SUFFIX,bdxiguastatic.com,选择代理
  - DOMAIN-SUFFIX,byted-static.com,选择代理
  - DOMAIN-SUFFIX,bytedance.com,选择代理
  - DOMAIN-SUFFIX,bytedance.net,选择代理
  - DOMAIN-SUFFIX,bytedns.net,选择代理
  - DOMAIN-SUFFIX,bytednsdoc.com,选择代理
  - DOMAIN-SUFFIX,bytegoofy.com,选择代理
  - DOMAIN-SUFFIX,byteimg.com,选择代理
  - DOMAIN-SUFFIX,bytescm.com,选择代理
  - DOMAIN-SUFFIX,bytetos.com,选择代理
  - DOMAIN-SUFFIX,bytexservice.com,选择代理
  - DOMAIN-SUFFIX,douyin.com,选择代理
  - DOMAIN-SUFFIX,douyincdn.com,选择代理
  - DOMAIN-SUFFIX,douyinpic.com,选择代理
  - DOMAIN-SUFFIX,douyinstatic.com,选择代理
  - DOMAIN-SUFFIX,douyinvod.com,选择代理
  - DOMAIN-SUFFIX,feelgood.cn,选择代理
  - DOMAIN-SUFFIX,feiliao.com,选择代理
  - DOMAIN-SUFFIX,gifshow.com,选择代理
  - DOMAIN-SUFFIX,huoshan.com,选择代理
  - DOMAIN-SUFFIX,huoshanzhibo.com,选择代理
  - DOMAIN-SUFFIX,ibytedapm.com,选择代理
  - DOMAIN-SUFFIX,iesdouyin.com,选择代理
  - DOMAIN-SUFFIX,ixigua.com,选择代理
  - DOMAIN-SUFFIX,kspkg.com,选择代理
  - DOMAIN-SUFFIX,pstatp.com,选择代理
  - DOMAIN-SUFFIX,snssdk.com,选择代理
  - DOMAIN-SUFFIX,toutiao.com,选择代理
  - DOMAIN-SUFFIX,toutiao13.com,选择代理
  - DOMAIN-SUFFIX,toutiaoapi.com,选择代理
  - DOMAIN-SUFFIX,toutiaocdn.com,选择代理
  - DOMAIN-SUFFIX,toutiaocdn.net,选择代理
  - DOMAIN-SUFFIX,toutiaocloud.com,选择代理
  - DOMAIN-SUFFIX,toutiaohao.com,选择代理
  - DOMAIN-SUFFIX,toutiaohao.net,选择代理
  - DOMAIN-SUFFIX,toutiaoimg.com,选择代理
  - DOMAIN-SUFFIX,toutiaopage.com,选择代理
  - DOMAIN-SUFFIX,wukong.com,选择代理
  - DOMAIN-SUFFIX,zijieapi.com,选择代理
  - DOMAIN-SUFFIX,zijieimg.com,选择代理
  - DOMAIN-SUFFIX,zjbyte.com,选择代理
  - DOMAIN-SUFFIX,zjcdn.com,选择代理
  - DOMAIN-SUFFIX,cctv.com,选择代理
  - DOMAIN-SUFFIX,cctvpic.com,选择代理
  - DOMAIN-SUFFIX,livechina.com,选择代理
  - DOMAIN-SUFFIX,21cn.com,选择代理
  - DOMAIN-SUFFIX,didialift.com,选择代理
  - DOMAIN-SUFFIX,didiglobal.com,选择代理
  - DOMAIN-SUFFIX,udache.com,选择代理
  - DOMAIN-SUFFIX,bytefcdnrd.com,选择代理
  - DOMAIN-SUFFIX,edgesrv.com,选择代理
  - DOMAIN-SUFFIX,douyu.com,选择代理
  - DOMAIN-SUFFIX,douyu.tv,选择代理
  - DOMAIN-SUFFIX,douyuscdn.com,选择代理
  - DOMAIN-SUFFIX,douyutv.com,选择代理
  - DOMAIN-SUFFIX,epicgames.com,选择代理
  - DOMAIN-SUFFIX,epicgames.dev,选择代理
  - DOMAIN-SUFFIX,helpshift.com,选择代理
  - DOMAIN-SUFFIX,paragon.com,选择代理
  - DOMAIN-SUFFIX,unrealengine.com,选择代理
  - DOMAIN-SUFFIX,dbankcdn.com,选择代理
  - DOMAIN-SUFFIX,hc-cdn.com,选择代理
  - DOMAIN-SUFFIX,hicloud.com,选择代理
  - DOMAIN-SUFFIX,hihonor.com,选择代理
  - DOMAIN-SUFFIX,huawei.com,选择代理
  - DOMAIN-SUFFIX,huaweicloud.com,选择代理
  - DOMAIN-SUFFIX,huaweishop.net,选择代理
  - DOMAIN-SUFFIX,hwccpc.com,选择代理
  - DOMAIN-SUFFIX,vmall.com,选择代理
  - DOMAIN-SUFFIX,vmallres.com,选择代理
  - DOMAIN-SUFFIX,allawnfs.com,选择代理
  - DOMAIN-SUFFIX,allawno.com,选择代理
  - DOMAIN-SUFFIX,allawntech.com,选择代理
  - DOMAIN-SUFFIX,coloros.com,选择代理
  - DOMAIN-SUFFIX,heytap.com,选择代理
  - DOMAIN-SUFFIX,heytapcs.com,选择代理
  - DOMAIN-SUFFIX,heytapdownload.com,选择代理
  - DOMAIN-SUFFIX,heytapimage.com,选择代理
  - DOMAIN-SUFFIX,heytapmobi.com,选择代理
  - DOMAIN-SUFFIX,oppo.com,选择代理
  - DOMAIN-SUFFIX,oppoer.me,选择代理
  - DOMAIN-SUFFIX,oppomobile.com,选择代理
  - DOMAIN-SUFFIX,iflyink.com,选择代理
  - DOMAIN-SUFFIX,iflyrec.com,选择代理
  - DOMAIN-SUFFIX,iflytek.com,选择代理
  - DOMAIN-SUFFIX,71.am,选择代理
  - DOMAIN-SUFFIX,71edge.com,选择代理
  - DOMAIN-SUFFIX,iqiyi.com,选择代理
  - DOMAIN-SUFFIX,iqiyipic.com,选择代理
  - DOMAIN-SUFFIX,ppsimg.com,选择代理
  - DOMAIN-SUFFIX,qiyi.com,选择代理
  - DOMAIN-SUFFIX,qiyipic.com,选择代理
  - DOMAIN-SUFFIX,qy.net,选择代理
  - DOMAIN-SUFFIX,360buy.com,选择代理
  - DOMAIN-SUFFIX,360buyimg.com,选择代理
  - DOMAIN-SUFFIX,jcloudcs.com,选择代理
  - DOMAIN-SUFFIX,jd.com,选择代理
  - DOMAIN-SUFFIX,jd.hk,选择代理
  - DOMAIN-SUFFIX,jdcloud.com,选择代理
  - DOMAIN-SUFFIX,jdpay.com,选择代理
  - DOMAIN-SUFFIX,paipai.com,选择代理
  - DOMAIN-SUFFIX,iciba.com,选择代理
  - DOMAIN-SUFFIX,ksosoft.com,选择代理
  - DOMAIN-SUFFIX,ksyun.com,选择代理
  - DOMAIN-SUFFIX,kuaishou.com,选择代理
  - DOMAIN-SUFFIX,yximgs.com,选择代理
  - DOMAIN-SUFFIX,meitu.com,选择代理
  - DOMAIN-SUFFIX,meitudata.com,选择代理
  - DOMAIN-SUFFIX,meitustat.com,选择代理
  - DOMAIN-SUFFIX,meipai.com,选择代理
  - DOMAIN-SUFFIX,le.com,选择代理
  - DOMAIN-SUFFIX,lecloud.com,选择代理
  - DOMAIN-SUFFIX,letv.com,选择代理
  - DOMAIN-SUFFIX,letvcloud.com,选择代理
  - DOMAIN-SUFFIX,letvimg.com,选择代理
  - DOMAIN-SUFFIX,letvlive.com,选择代理
  - DOMAIN-SUFFIX,letvstore.com,选择代理
  - DOMAIN-SUFFIX,hitv.com,选择代理
  - DOMAIN-SUFFIX,hunantv.com,选择代理
  - DOMAIN-SUFFIX,mgtv.com,选择代理
  - DOMAIN-SUFFIX,duokan.com,选择代理
  - DOMAIN-SUFFIX,mi-img.com,选择代理
  - DOMAIN-SUFFIX,mi.com,选择代理
  - DOMAIN-SUFFIX,miui.com,选择代理
  - DOMAIN-SUFFIX,xiaomi.com,选择代理
  - DOMAIN-SUFFIX,xiaomi.net,选择代理
  - DOMAIN-SUFFIX,xiaomicp.com,选择代理
  - DOMAIN-SUFFIX,126.com,选择代理
  - DOMAIN-SUFFIX,126.net,选择代理
  - DOMAIN-SUFFIX,127.net,选择代理
  - DOMAIN-SUFFIX,163.com,选择代理
  - DOMAIN-SUFFIX,163yun.com,选择代理
  - DOMAIN-SUFFIX,lofter.com,选择代理
  - DOMAIN-SUFFIX,netease.com,选择代理
  - DOMAIN-SUFFIX,ydstatic.com,选择代理
  - DOMAIN-SUFFIX,youdao.com,选择代理
  - DOMAIN-SUFFIX,pplive.com,选择代理
  - DOMAIN-SUFFIX,pptv.com,选择代理
  - DOMAIN-SUFFIX,pinduoduo.com,选择代理
  - DOMAIN-SUFFIX,yangkeduo.com,选择代理
  - DOMAIN-SUFFIX,leju.com,选择代理
  - DOMAIN-SUFFIX,miaopai.com,选择代理
  - DOMAIN-SUFFIX,sina.com,选择代理
  - DOMAIN-SUFFIX,sina.com.cn,选择代理
  - DOMAIN-SUFFIX,sina.cn,选择代理
  - DOMAIN-SUFFIX,sinaapp.com,选择代理
  - DOMAIN-SUFFIX,sinaapp.cn,选择代理
  - DOMAIN-SUFFIX,sinaimg.com,选择代理
  - DOMAIN-SUFFIX,sinaimg.cn,选择代理
  - DOMAIN-SUFFIX,weibo.com,选择代理
  - DOMAIN-SUFFIX,weibo.cn,选择代理
  - DOMAIN-SUFFIX,weibocdn.com,选择代理
  - DOMAIN-SUFFIX,weibocdn.cn,选择代理
  - DOMAIN-SUFFIX,xiaoka.tv,选择代理
  - DOMAIN-SUFFIX,go2map.com,选择代理
  - DOMAIN-SUFFIX,sogo.com,选择代理
  - DOMAIN-SUFFIX,sogou.com,选择代理
  - DOMAIN-SUFFIX,sogoucdn.com,选择代理
  - DOMAIN-SUFFIX,sohu-inc.com,选择代理
  - DOMAIN-SUFFIX,sohu.com,选择代理
  - DOMAIN-SUFFIX,sohucs.com,选择代理
  - DOMAIN-SUFFIX,sohuno.com,选择代理
  - DOMAIN-SUFFIX,sohurdc.com,选择代理
  - DOMAIN-SUFFIX,v-56.com,选择代理
  - DOMAIN-SUFFIX,playstation.com,选择代理
  - DOMAIN-SUFFIX,playstation.net,选择代理
  - DOMAIN-SUFFIX,playstationnetwork.com,选择代理
  - DOMAIN-SUFFIX,sony.com,选择代理
  - DOMAIN-SUFFIX,sonyentertainmentnetwork.com,选择代理
  - DOMAIN-SUFFIX,cm.steampowered.com,选择代理
  - DOMAIN-SUFFIX,steamcontent.com,选择代理
  - DOMAIN-SUFFIX,steamusercontent.com,选择代理
  - DOMAIN-SUFFIX,steamchina.com,选择代理
  - DOMAIN,csgo.wmsj.cn,选择代理
  - DOMAIN,dota2.wmsj.cn,选择代理
  - DOMAIN,wmsjsteam.com,选择代理
  - DOMAIN,dl.steam.clngaa.com,选择代理
  - DOMAIN,dl.steam.ksyna.com,选择代理
  - DOMAIN,st.dl.bscstorage.net,选择代理
  - DOMAIN,st.dl.eccdnx.com,选择代理
  - DOMAIN,st.dl.pinyuncloud.com,选择代理
  - DOMAIN,xz.pphimalayanrt.com,选择代理
  - DOMAIN,steampipe.steamcontent.tnkjmec.com,选择代理
  - DOMAIN,steampowered.com.8686c.com,选择代理
  - DOMAIN,steamstatic.com.8686c.com,选择代理
  - DOMAIN-SUFFIX,foxmail.com,选择代理
  - DOMAIN-SUFFIX,gtimg.com,选择代理
  - DOMAIN-SUFFIX,idqqimg.com,选择代理
  - DOMAIN-SUFFIX,igamecj.com,选择代理
  - DOMAIN-SUFFIX,myapp.com,选择代理
  - DOMAIN-SUFFIX,myqcloud.com,选择代理
  - DOMAIN-SUFFIX,qq.com,选择代理
  - DOMAIN-SUFFIX,qqmail.com,选择代理
  - DOMAIN-SUFFIX,qqurl.com,选择代理
  - DOMAIN-SUFFIX,smtcdns.com,选择代理
  - DOMAIN-SUFFIX,smtcdns.net,选择代理
  - DOMAIN-SUFFIX,soso.com,选择代理
  - DOMAIN-SUFFIX,tencent-cloud.net,选择代理
  - DOMAIN-SUFFIX,tencent.com,选择代理
  - DOMAIN-SUFFIX,tencentmind.com,选择代理
  - DOMAIN-SUFFIX,tenpay.com,选择代理
  - DOMAIN-SUFFIX,wechat.com,选择代理
  - DOMAIN-SUFFIX,weixin.com,选择代理
  - DOMAIN-SUFFIX,weiyun.com,选择代理
  - DOMAIN-SUFFIX,appsimg.com,选择代理
  - DOMAIN-SUFFIX,appvipshop.com,选择代理
  - DOMAIN-SUFFIX,vip.com,选择代理
  - DOMAIN-SUFFIX,vipstatic.com,选择代理
  - DOMAIN-SUFFIX,ximalaya.com,选择代理
  - DOMAIN-SUFFIX,xmcdn.com,选择代理
  - DOMAIN-SUFFIX,00cdn.com,选择代理
  - DOMAIN-SUFFIX,88cdn.com,选择代理
  - DOMAIN-SUFFIX,kanimg.com,选择代理
  - DOMAIN-SUFFIX,kankan.com,选择代理
  - DOMAIN-SUFFIX,p2cdn.com,选择代理
  - DOMAIN-SUFFIX,sandai.net,选择代理
  - DOMAIN-SUFFIX,thundercdn.com,选择代理
  - DOMAIN-SUFFIX,xunlei.com,选择代理
  - DOMAIN-SUFFIX,got001.com,选择代理
  - DOMAIN-SUFFIX,p4pfile.com,选择代理
  - DOMAIN-SUFFIX,rrys.tv,选择代理
  - DOMAIN-SUFFIX,rrys2020.com,选择代理
  - DOMAIN-SUFFIX,yyets.com,选择代理
  - DOMAIN-SUFFIX,zimuzu.io,选择代理
  - DOMAIN-SUFFIX,zimuzu.tv,选择代理
  - DOMAIN-SUFFIX,zmz001.com,选择代理
  - DOMAIN-SUFFIX,zmz002.com,选择代理
  - DOMAIN-SUFFIX,zmz003.com,选择代理
  - DOMAIN-SUFFIX,zmz004.com,选择代理
  - DOMAIN-SUFFIX,zmz2019.com,选择代理
  - DOMAIN-SUFFIX,zmzapi.com,选择代理
  - DOMAIN-SUFFIX,zmzapi.net,选择代理
  - DOMAIN-SUFFIX,zmzfile.com,选择代理
  - DOMAIN-SUFFIX,teamviewer.com,选择代理
  - IP-CIDR,139.220.243.27/32,选择代理,no-resolve
  - IP-CIDR,172.16.102.56/32,选择代理,no-resolve
  - IP-CIDR,185.188.32.1/28,选择代理,no-resolve
  - IP-CIDR,221.226.128.146/32,选择代理,no-resolve
  - IP-CIDR6,2a0b:b580::/48,选择代理,no-resolve
  - IP-CIDR6,2a0b:b581::/48,选择代理,no-resolve
  - IP-CIDR6,2a0b:b582::/48,选择代理,no-resolve
  - IP-CIDR6,2a0b:b583::/48,选择代理,no-resolve
  - DOMAIN-SUFFIX,baomitu.com,选择代理
  - DOMAIN-SUFFIX,bootcss.com,选择代理
  - DOMAIN-SUFFIX,jiasule.com,选择代理
  - DOMAIN-SUFFIX,staticfile.org,选择代理
  - DOMAIN-SUFFIX,upaiyun.com,选择代理
  - DOMAIN-SUFFIX,doh.pub,选择代理
  - DOMAIN-SUFFIX,dns.alidns.com,选择代理
  - DOMAIN-SUFFIX,doh.360.cn,选择代理
  - IP-CIDR,1.12.12.12/32,选择代理,no-resolve
  - DOMAIN-SUFFIX,10010.com,选择代理
  - DOMAIN-SUFFIX,115.com,选择代理
  - DOMAIN-SUFFIX,12306.com,选择代理
  - DOMAIN-SUFFIX,17173.com,选择代理
  - DOMAIN-SUFFIX,178.com,选择代理
  - DOMAIN-SUFFIX,17k.com,选择代理
  - DOMAIN-SUFFIX,360doc.com,选择代理
  - DOMAIN-SUFFIX,36kr.com,选择代理
  - DOMAIN-SUFFIX,3dmgame.com,选择代理
  - DOMAIN-SUFFIX,51cto.com,选择代理
  - DOMAIN-SUFFIX,51job.com,选择代理
  - DOMAIN-SUFFIX,51jobcdn.com,选择代理
  - DOMAIN-SUFFIX,56.com,选择代理
  - DOMAIN-SUFFIX,8686c.com,选择代理
  - DOMAIN-SUFFIX,abchina.com,选择代理
  - DOMAIN-SUFFIX,abercrombie.com,选择代理
  - DOMAIN-SUFFIX,acfun.tv,选择代理
  - DOMAIN-SUFFIX,air-matters.com,选择代理
  - DOMAIN-SUFFIX,air-matters.io,选择代理
  - DOMAIN-SUFFIX,aixifan.com,选择代理
  - DOMAIN-SUFFIX,algocasts.io,选择代理
  - DOMAIN-SUFFIX,babytree.com,选择代理
  - DOMAIN-SUFFIX,babytreeimg.com,选择代理
  - DOMAIN-SUFFIX,baicizhan.com,选择代理
  - DOMAIN-SUFFIX,baidupan.com,选择代理
  - DOMAIN-SUFFIX,baike.com,选择代理
  - DOMAIN-SUFFIX,biqudu.com,选择代理
  - DOMAIN-SUFFIX,biquge.com,选择代理
  - DOMAIN-SUFFIX,bitauto.com,选择代理
  - DOMAIN-SUFFIX,bosszhipin.com,选择代理
  - DOMAIN-SUFFIX,c-ctrip.com,选择代理
  - DOMAIN-SUFFIX,camera360.com,选择代理
  - DOMAIN-SUFFIX,cdnmama.com,选择代理
  - DOMAIN-SUFFIX,chaoxing.com,选择代理
  - DOMAIN-SUFFIX,che168.com,选择代理
  - DOMAIN-SUFFIX,chinacache.net,选择代理
  - DOMAIN-SUFFIX,chinaso.com,选择代理
  - DOMAIN-SUFFIX,chinaz.com,选择代理
  - DOMAIN-SUFFIX,chinaz.net,选择代理
  - DOMAIN-SUFFIX,chuimg.com,选择代理
  - DOMAIN-SUFFIX,cibntv.net,选择代理
  - DOMAIN-SUFFIX,clouddn.com,选择代理
  - DOMAIN-SUFFIX,cloudxns.net,选择代理
  - DOMAIN-SUFFIX,cn163.net,选择代理
  - DOMAIN-SUFFIX,cnblogs.com,选择代理
  - DOMAIN-SUFFIX,cnki.net,选择代理
  - DOMAIN-SUFFIX,cnmstl.net,选择代理
  - DOMAIN-SUFFIX,coolapk.com,选择代理
  - DOMAIN-SUFFIX,coolapkmarket.com,选择代理
  - DOMAIN-SUFFIX,csdn.net,选择代理
  - DOMAIN-SUFFIX,ctrip.com,选择代理
  - DOMAIN-SUFFIX,dangdang.com,选择代理
  - DOMAIN-SUFFIX,dfcfw.com,选择代理
  - DOMAIN-SUFFIX,dianping.com,选择代理
  - DOMAIN-SUFFIX,dilidili.wang,选择代理
  - DOMAIN-SUFFIX,douban.com,选择代理
  - DOMAIN-SUFFIX,doubanio.com,选择代理
  - DOMAIN-SUFFIX,dpfile.com,选择代理
  - DOMAIN-SUFFIX,duowan.com,选择代理
  - DOMAIN-SUFFIX,dxycdn.com,选择代理
  - DOMAIN-SUFFIX,dytt8.net,选择代理
  - DOMAIN-SUFFIX,easou.com,选择代理
  - DOMAIN-SUFFIX,eastday.com,选择代理
  - DOMAIN-SUFFIX,eastmoney.com,选择代理
  - DOMAIN-SUFFIX,ecitic.com,选择代理
  - DOMAIN-SUFFIX,element-plus.org,选择代理
  - DOMAIN-SUFFIX,ewqcxz.com,选择代理
  - DOMAIN-SUFFIX,fang.com,选择代理
  - DOMAIN-SUFFIX,fantasy.tv,选择代理
  - DOMAIN-SUFFIX,feng.com,选择代理
  - DOMAIN-SUFFIX,fengkongcloud.com,选择代理
  - DOMAIN-SUFFIX,fir.im,选择代理
  - DOMAIN-SUFFIX,frdic.com,选择代理
  - DOMAIN-SUFFIX,fresh-ideas.cc,选择代理
  - DOMAIN-SUFFIX,ganji.com,选择代理
  - DOMAIN-SUFFIX,ganjistatic1.com,选择代理
  - DOMAIN-SUFFIX,geetest.com,选择代理
  - DOMAIN-SUFFIX,geilicdn.com,选择代理
  - DOMAIN-SUFFIX,ghpym.com,选择代理
  - DOMAIN-SUFFIX,godic.net,选择代理
  - DOMAIN-SUFFIX,guazi.com,选择代理
  - DOMAIN-SUFFIX,gwdang.com,选择代理
  - DOMAIN-SUFFIX,gzlzfm.com,选择代理
  - DOMAIN-SUFFIX,haibian.com,选择代理
  - DOMAIN-SUFFIX,haosou.com,选择代理
  - DOMAIN-SUFFIX,hollisterco.com,选择代理
  - DOMAIN-SUFFIX,hongxiu.com,选择代理
  - DOMAIN-SUFFIX,huajiao.com,选择代理
  - DOMAIN-SUFFIX,hupu.com,选择代理
  - DOMAIN-SUFFIX,huxiucdn.com,选择代理
  - DOMAIN-SUFFIX,huya.com,选择代理
  - DOMAIN-SUFFIX,ifeng.com,选择代理
  - DOMAIN-SUFFIX,ifengimg.com,选择代理
  - DOMAIN-SUFFIX,images-amazon.com,选择代理
  - DOMAIN-SUFFIX,infzm.com,选择代理
  - DOMAIN-SUFFIX,ipip.net,选择代理
  - DOMAIN-SUFFIX,it168.com,选择代理
  - DOMAIN-SUFFIX,ithome.com,选择代理
  - DOMAIN-SUFFIX,ixdzs.com,选择代理
  - DOMAIN-SUFFIX,jianguoyun.com,选择代理
  - DOMAIN-SUFFIX,jianshu.com,选择代理
  - DOMAIN-SUFFIX,jianshu.io,选择代理
  - DOMAIN-SUFFIX,jianshuapi.com,选择代理
  - DOMAIN-SUFFIX,jiathis.com,选择代理
  - DOMAIN-SUFFIX,jmstatic.com,选择代理
  - DOMAIN-SUFFIX,jumei.com,选择代理
  - DOMAIN-SUFFIX,kaola.com,选择代理
  - DOMAIN-SUFFIX,knewone.com,选择代理
  - DOMAIN-SUFFIX,koowo.com,选择代理
  - DOMAIN-SUFFIX,koyso.com,选择代理
  - DOMAIN-SUFFIX,ksyungslb.com,选择代理
  - DOMAIN-SUFFIX,kuaidi100.com,选择代理
  - DOMAIN-SUFFIX,kugou.com,选择代理
  - DOMAIN-SUFFIX,lancdns.com,选择代理
  - DOMAIN-SUFFIX,landiannews.com,选择代理
  - DOMAIN-SUFFIX,lanzou.com,选择代理
  - DOMAIN-SUFFIX,lanzoui.com,选择代理
  - DOMAIN-SUFFIX,lanzoux.com,选择代理
  - DOMAIN-SUFFIX,lemicp.com,选择代理
  - DOMAIN-SUFFIX,letitfly.me,选择代理
  - DOMAIN-SUFFIX,lizhi.fm,选择代理
  - DOMAIN-SUFFIX,lizhi.io,选择代理
  - DOMAIN-SUFFIX,lizhifm.com,选择代理
  - DOMAIN-SUFFIX,luoo.net,选择代理
  - DOMAIN-SUFFIX,lvmama.com,选择代理
  - DOMAIN-SUFFIX,lxdns.com,选择代理
  - DOMAIN-SUFFIX,maoyan.com,选择代理
  - DOMAIN-SUFFIX,meilishuo.com,选择代理
  - DOMAIN-SUFFIX,meituan.com,选择代理
  - DOMAIN-SUFFIX,meituan.net,选择代理
  - DOMAIN-SUFFIX,meizu.com,选择代理
  - DOMAIN-SUFFIX,migucloud.com,选择代理
  - DOMAIN-SUFFIX,miguvideo.com,选择代理
  - DOMAIN-SUFFIX,mobike.com,选择代理
  - DOMAIN-SUFFIX,mogu.com,选择代理
  - DOMAIN-SUFFIX,mogucdn.com,选择代理
  - DOMAIN-SUFFIX,mogujie.com,选择代理
  - DOMAIN-SUFFIX,moji.com,选择代理
  - DOMAIN-SUFFIX,moke.com,选择代理
  - DOMAIN-SUFFIX,msstatic.com,选择代理
  - DOMAIN-SUFFIX,mubu.com,选择代理
  - DOMAIN-SUFFIX,myunlu.com,选择代理
  - DOMAIN-SUFFIX,nruan.com,选择代理
  - DOMAIN-SUFFIX,nuomi.com,选择代理
  - DOMAIN-SUFFIX,onedns.net,选择代理
  - DOMAIN-SUFFIX,oneplus.com,选择代理
  - DOMAIN-SUFFIX,onlinedown.net,选择代理
  - DOMAIN-SUFFIX,oracle.com,选择代理
  - DOMAIN-SUFFIX,oschina.net,选择代理
  - DOMAIN-SUFFIX,ourdvs.com,选择代理
  - DOMAIN-SUFFIX,polyv.net,选择代理
  - DOMAIN-SUFFIX,qbox.me,选择代理
  - DOMAIN-SUFFIX,qcloud.com,选择代理
  - DOMAIN-SUFFIX,qcloudcdn.com,选择代理
  - DOMAIN-SUFFIX,qdaily.com,选择代理
  - DOMAIN-SUFFIX,qdmm.com,选择代理
  - DOMAIN-SUFFIX,qhimg.com,选择代理
  - DOMAIN-SUFFIX,qianqian.com,选择代理
  - DOMAIN-SUFFIX,qidian.com,选择代理
  - DOMAIN-SUFFIX,qihucdn.com,选择代理
  - DOMAIN-SUFFIX,qin.io,选择代理
  - DOMAIN-SUFFIX,qiniu.com,选择代理
  - DOMAIN-SUFFIX,qiniucdn.com,选择代理
  - DOMAIN-SUFFIX,qiniudn.com,选择代理
  - DOMAIN-SUFFIX,qiushibaike.com,选择代理
  - DOMAIN-SUFFIX,quanmin.tv,选择代理
  - DOMAIN-SUFFIX,qunar.com,选择代理
  - DOMAIN-SUFFIX,qunarzz.com,选择代理
  - DOMAIN-SUFFIX,realme.com,选择代理
  - DOMAIN-SUFFIX,repaik.com,选择代理
  - DOMAIN-SUFFIX,ruguoapp.com,选择代理
  - DOMAIN-SUFFIX,runoob.com,选择代理
  - DOMAIN-SUFFIX,sankuai.com,选择代理
  - DOMAIN-SUFFIX,segmentfault.com,选择代理
  - DOMAIN-SUFFIX,sf-express.com,选择代理
  - DOMAIN-SUFFIX,shumilou.net,选择代理
  - DOMAIN-SUFFIX,simplecd.me,选择代理
  - DOMAIN-SUFFIX,smzdm.com,选择代理
  - DOMAIN-SUFFIX,snwx.com,选择代理
  - DOMAIN-SUFFIX,soufunimg.com,选择代理
  - DOMAIN-SUFFIX,sspai.com,选择代理
  - DOMAIN-SUFFIX,startssl.com,选择代理
  - DOMAIN-SUFFIX,suning.com,选择代理
  - DOMAIN-SUFFIX,synology.com,选择代理
  - DOMAIN-SUFFIX,taihe.com,选择代理
  - DOMAIN-SUFFIX,th-sjy.com,选择代理
  - DOMAIN-SUFFIX,tianqi.com,选择代理
  - DOMAIN-SUFFIX,tianqistatic.com,选择代理
  - DOMAIN-SUFFIX,tianyancha.com,选择代理
  - DOMAIN-SUFFIX,tianyaui.com,选择代理
  - DOMAIN-SUFFIX,tietuku.com,选择代理
  - DOMAIN-SUFFIX,tiexue.net,选择代理
  - DOMAIN-SUFFIX,tmiaoo.com,选择代理
  - DOMAIN-SUFFIX,trip.com,选择代理
  - DOMAIN-SUFFIX,ttmeiju.com,选择代理
  - DOMAIN-SUFFIX,tudou.com,选择代理
  - DOMAIN-SUFFIX,tuniu.com,选择代理
  - DOMAIN-SUFFIX,tuniucdn.com,选择代理
  - DOMAIN-SUFFIX,umengcloud.com,选择代理
  - DOMAIN-SUFFIX,upyun.com,选择代理
  - DOMAIN-SUFFIX,uxengine.net,选择代理
  - DOMAIN-SUFFIX,videocc.net,选择代理
  - DOMAIN-SUFFIX,vivo.com,选择代理
  - DOMAIN-SUFFIX,wandoujia.com,选择代理
  - DOMAIN-SUFFIX,weather.com,选择代理
  - DOMAIN-SUFFIX,weico.cc,选择代理
  - DOMAIN-SUFFIX,weidian.com,选择代理
  - DOMAIN-SUFFIX,weiphone.com,选择代理
  - DOMAIN-SUFFIX,weiphone.net,选择代理
  - DOMAIN-SUFFIX,womai.com,选择代理
  - DOMAIN-SUFFIX,wscdns.com,选择代理
  - DOMAIN-SUFFIX,xdrig.com,选择代理
  - DOMAIN-SUFFIX,xhscdn.com,选择代理
  - DOMAIN-SUFFIX,xiachufang.com,选择代理
  - DOMAIN-SUFFIX,xiaohongshu.com,选择代理
  - DOMAIN-SUFFIX,xiaojukeji.com,选择代理
  - DOMAIN-SUFFIX,xinhuanet.com,选择代理
  - DOMAIN-SUFFIX,xip.io,选择代理
  - DOMAIN-SUFFIX,xitek.com,选择代理
  - DOMAIN-SUFFIX,xiumi.us,选择代理
  - DOMAIN-SUFFIX,xslb.net,选择代理
  - DOMAIN-SUFFIX,xueqiu.com,选择代理
  - DOMAIN-SUFFIX,yach.me,选择代理
  - DOMAIN-SUFFIX,yeepay.com,选择代理
  - DOMAIN-SUFFIX,yhd.com,选择代理
  - DOMAIN-SUFFIX,yihaodianimg.com,选择代理
  - DOMAIN-SUFFIX,yinxiang.com,选择代理
  - DOMAIN-SUFFIX,yinyuetai.com,选择代理
  - DOMAIN-SUFFIX,yixia.com,选择代理
  - DOMAIN-SUFFIX,ys168.com,选择代理
  - DOMAIN-SUFFIX,yuewen.com,选择代理
  - DOMAIN-SUFFIX,yy.com,选择代理
  - DOMAIN-SUFFIX,yystatic.com,选择代理
  - DOMAIN-SUFFIX,zealer.com,选择代理
  - DOMAIN-SUFFIX,zhangzishi.cc,选择代理
  - DOMAIN-SUFFIX,zhanqi.tv,选择代理
  - DOMAIN-SUFFIX,zhaopin.com,选择代理
  - DOMAIN-SUFFIX,zhihu.com,选择代理
  - DOMAIN-SUFFIX,zhimg.com,选择代理
  - DOMAIN-SUFFIX,zhipin.com,选择代理
  - DOMAIN-SUFFIX,zhongsou.com,选择代理
  - DOMAIN-SUFFIX,zhuihd.com,选择代理
  - IP-CIDR,8.128.0.0/10,选择代理,no-resolve
  - IP-CIDR,8.208.0.0/12,选择代理,no-resolve
  - IP-CIDR,14.1.112.0/22,选择代理,no-resolve
  - IP-CIDR,41.222.240.0/22,选择代理,no-resolve
  - IP-CIDR,41.223.119.0/24,选择代理,no-resolve
  - IP-CIDR,43.242.168.0/22,选择代理,no-resolve
  - IP-CIDR,45.112.212.0/22,选择代理,no-resolve
  - IP-CIDR,47.52.0.0/16,选择代理,no-resolve
  - IP-CIDR,47.56.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.74.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.76.0.0/14,选择代理,no-resolve
  - IP-CIDR,47.80.0.0/12,选择代理,no-resolve
  - IP-CIDR,47.235.0.0/16,选择代理,no-resolve
  - IP-CIDR,47.236.0.0/14,选择代理,no-resolve
  - IP-CIDR,47.240.0.0/14,选择代理,no-resolve
  - IP-CIDR,47.244.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.246.0.0/16,选择代理,no-resolve
  - IP-CIDR,47.250.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.252.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.254.0.0/16,选择代理,no-resolve
  - IP-CIDR,59.82.0.0/20,选择代理,no-resolve
  - IP-CIDR,59.82.240.0/21,选择代理,no-resolve
  - IP-CIDR,59.82.248.0/22,选择代理,no-resolve
  - IP-CIDR,72.254.0.0/16,选择代理,no-resolve
  - IP-CIDR,103.38.56.0/22,选择代理,no-resolve
  - IP-CIDR,103.52.76.0/22,选择代理,no-resolve
  - IP-CIDR,103.206.40.0/22,选择代理,no-resolve
  - IP-CIDR,110.76.21.0/24,选择代理,no-resolve
  - IP-CIDR,110.76.23.0/24,选择代理,no-resolve
  - IP-CIDR,112.125.0.0/17,选择代理,no-resolve
  - IP-CIDR,116.251.64.0/18,选择代理,no-resolve
  - IP-CIDR,119.38.208.0/20,选择代理,no-resolve
  - IP-CIDR,119.38.224.0/20,选择代理,no-resolve
  - IP-CIDR,119.42.224.0/20,选择代理,no-resolve
  - IP-CIDR,139.95.0.0/16,选择代理,no-resolve
  - IP-CIDR,140.205.1.0/24,选择代理,no-resolve
  - IP-CIDR,140.205.122.0/24,选择代理,no-resolve
  - IP-CIDR,147.139.0.0/16,选择代理,no-resolve
  - IP-CIDR,149.129.0.0/16,选择代理,no-resolve
  - IP-CIDR,155.102.0.0/16,选择代理,no-resolve
  - IP-CIDR,161.117.0.0/16,选择代理,no-resolve
  - IP-CIDR,163.181.0.0/16,选择代理,no-resolve
  - IP-CIDR,170.33.0.0/16,选择代理,no-resolve
  - IP-CIDR,198.11.128.0/18,选择代理,no-resolve
  - IP-CIDR,205.204.96.0/19,选择代理,no-resolve
  - IP-CIDR,19.28.0.0/23,选择代理,no-resolve
  - IP-CIDR,45.40.192.0/19,选择代理,no-resolve
  - IP-CIDR,49.51.0.0/16,选择代理,no-resolve
  - IP-CIDR,62.234.0.0/16,选择代理,no-resolve
  - IP-CIDR,94.191.0.0/17,选择代理,no-resolve
  - IP-CIDR,103.7.28.0/22,选择代理,no-resolve
  - IP-CIDR,103.116.50.0/23,选择代理,no-resolve
  - IP-CIDR,103.231.60.0/24,选择代理,no-resolve
  - IP-CIDR,109.244.0.0/16,选择代理,no-resolve
  - IP-CIDR,111.30.128.0/21,选择代理,no-resolve
  - IP-CIDR,111.30.136.0/24,选择代理,no-resolve
  - IP-CIDR,111.30.139.0/24,选择代理,no-resolve
  - IP-CIDR,111.30.140.0/23,选择代理,no-resolve
  - IP-CIDR,115.159.0.0/16,选择代理,no-resolve
  - IP-CIDR,119.28.0.0/15,选择代理,no-resolve
  - IP-CIDR,120.88.56.0/23,选择代理,no-resolve
  - IP-CIDR,121.51.0.0/16,选择代理,no-resolve
  - IP-CIDR,129.28.0.0/16,选择代理,no-resolve
  - IP-CIDR,129.204.0.0/16,选择代理,no-resolve
  - IP-CIDR,129.211.0.0/16,选择代理,no-resolve
  - IP-CIDR,132.232.0.0/16,选择代理,no-resolve
  - IP-CIDR,134.175.0.0/16,选择代理,no-resolve
  - IP-CIDR,146.56.192.0/18,选择代理,no-resolve
  - IP-CIDR,148.70.0.0/16,选择代理,no-resolve
  - IP-CIDR,150.109.0.0/16,选择代理,no-resolve
  - IP-CIDR,152.136.0.0/16,选择代理,no-resolve
  - IP-CIDR,162.14.0.0/16,选择代理,no-resolve
  - IP-CIDR,162.62.0.0/16,选择代理,no-resolve
  - IP-CIDR,170.106.130.0/24,选择代理,no-resolve
  - IP-CIDR,182.254.0.0/16,选择代理,no-resolve
  - IP-CIDR,188.131.128.0/17,选择代理,no-resolve
  - IP-CIDR,203.195.128.0/17,选择代理,no-resolve
  - IP-CIDR,203.205.128.0/17,选择代理,no-resolve
  - IP-CIDR,210.4.138.0/24,选择代理,no-resolve
  - IP-CIDR,211.152.128.0/23,选择代理,no-resolve
  - IP-CIDR,211.152.132.0/23,选择代理,no-resolve
  - IP-CIDR,211.152.148.0/23,选择代理,no-resolve
  - IP-CIDR,212.64.0.0/17,选择代理,no-resolve
  - IP-CIDR,212.129.128.0/17,选择代理,no-resolve
  - IP-CIDR,45.113.192.0/22,选择代理,no-resolve
  - IP-CIDR,63.217.23.0/24,选择代理,no-resolve
  - IP-CIDR,63.243.252.0/24,选择代理,no-resolve
  - IP-CIDR,103.235.44.0/22,选择代理,no-resolve
  - IP-CIDR,104.193.88.0/22,选择代理,no-resolve
  - IP-CIDR,106.12.0.0/15,选择代理,no-resolve
  - IP-CIDR,114.28.224.0/20,选择代理,no-resolve
  - IP-CIDR,119.63.192.0/21,选择代理,no-resolve
  - IP-CIDR,180.76.0.0/24,选择代理,no-resolve
  - IP-CIDR,180.76.0.0/16,选择代理,no-resolve
  - IP-CIDR,182.61.0.0/16,选择代理,no-resolve
  - IP-CIDR,185.10.104.0/22,选择代理,no-resolve
  - IP-CIDR,202.46.48.0/20,选择代理,no-resolve
  - IP-CIDR,203.90.238.0/24,选择代理,no-resolve
  - IP-CIDR,43.254.0.0/22,选择代理,no-resolve
  - IP-CIDR,45.249.212.0/22,选择代理,no-resolve
  - IP-CIDR,49.4.0.0/17,选择代理,no-resolve
  - IP-CIDR,78.101.192.0/19,选择代理,no-resolve
  - IP-CIDR,78.101.224.0/20,选择代理,no-resolve
  - IP-CIDR,81.52.161.0/24,选择代理,no-resolve
  - IP-CIDR,85.97.220.0/22,选择代理,no-resolve
  - IP-CIDR,103.31.200.0/22,选择代理,no-resolve
  - IP-CIDR,103.69.140.0/23,选择代理,no-resolve
  - IP-CIDR,103.218.216.0/22,选择代理,no-resolve
  - IP-CIDR,114.115.128.0/17,选择代理,no-resolve
  - IP-CIDR,114.116.0.0/16,选择代理,no-resolve
  - IP-CIDR,116.63.128.0/18,选择代理,no-resolve
  - IP-CIDR,116.66.184.0/22,选择代理,no-resolve
  - IP-CIDR,116.71.96.0/20,选择代理,no-resolve
  - IP-CIDR,116.71.128.0/21,选择代理,no-resolve
  - IP-CIDR,116.71.136.0/22,选择代理,no-resolve
  - IP-CIDR,116.71.141.0/24,选择代理,no-resolve
  - IP-CIDR,116.71.142.0/24,选择代理,no-resolve
  - IP-CIDR,116.71.243.0/24,选择代理,no-resolve
  - IP-CIDR,116.71.244.0/24,选择代理,no-resolve
  - IP-CIDR,116.71.251.0/24,选择代理,no-resolve
  - IP-CIDR,117.78.0.0/18,选择代理,no-resolve
  - IP-CIDR,119.3.0.0/16,选择代理,no-resolve
  - IP-CIDR,119.8.0.0/21,选择代理,no-resolve
  - IP-CIDR,119.8.32.0/19,选择代理,no-resolve
  - IP-CIDR,121.36.0.0/17,选择代理,no-resolve
  - IP-CIDR,121.36.128.0/18,选择代理,no-resolve
  - IP-CIDR,121.37.0.0/17,选择代理,no-resolve
  - IP-CIDR,122.112.128.0/17,选择代理,no-resolve
  - IP-CIDR,139.9.0.0/18,选择代理,no-resolve
  - IP-CIDR,139.9.64.0/19,选择代理,no-resolve
  - IP-CIDR,139.9.100.0/22,选择代理,no-resolve
  - IP-CIDR,139.9.104.0/21,选择代理,no-resolve
  - IP-CIDR,139.9.112.0/20,选择代理,no-resolve
  - IP-CIDR,139.9.128.0/18,选择代理,no-resolve
  - IP-CIDR,139.9.192.0/19,选择代理,no-resolve
  - IP-CIDR,139.9.224.0/20,选择代理,no-resolve
  - IP-CIDR,139.9.240.0/21,选择代理,no-resolve
  - IP-CIDR,139.9.248.0/22,选择代理,no-resolve
  - IP-CIDR,139.159.128.0/19,选择代理,no-resolve
  - IP-CIDR,139.159.160.0/22,选择代理,no-resolve
  - IP-CIDR,139.159.164.0/23,选择代理,no-resolve
  - IP-CIDR,139.159.168.0/21,选择代理,no-resolve
  - IP-CIDR,139.159.176.0/20,选择代理,no-resolve
  - IP-CIDR,139.159.192.0/18,选择代理,no-resolve
  - IP-CIDR,159.138.0.0/18,选择代理,no-resolve
  - IP-CIDR,159.138.64.0/21,选择代理,no-resolve
  - IP-CIDR,159.138.79.0/24,选择代理,no-resolve
  - IP-CIDR,159.138.80.0/20,选择代理,no-resolve
  - IP-CIDR,159.138.96.0/20,选择代理,no-resolve
  - IP-CIDR,159.138.112.0/21,选择代理,no-resolve
  - IP-CIDR,159.138.125.0/24,选择代理,no-resolve
  - IP-CIDR,159.138.128.0/18,选择代理,no-resolve
  - IP-CIDR,159.138.192.0/20,选择代理,no-resolve
  - IP-CIDR,159.138.223.0/24,选择代理,no-resolve
  - IP-CIDR,159.138.224.0/19,选择代理,no-resolve
  - IP-CIDR,168.195.92.0/22,选择代理,no-resolve
  - IP-CIDR,185.176.76.0/22,选择代理,no-resolve
  - IP-CIDR,197.199.0.0/18,选择代理,no-resolve
  - IP-CIDR,197.210.163.0/24,选择代理,no-resolve
  - IP-CIDR,197.252.1.0/24,选择代理,no-resolve
  - IP-CIDR,197.252.2.0/23,选择代理,no-resolve
  - IP-CIDR,197.252.4.0/22,选择代理,no-resolve
  - IP-CIDR,197.252.8.0/21,选择代理,no-resolve
  - IP-CIDR,200.32.52.0/24,选择代理,no-resolve
  - IP-CIDR,200.32.54.0/24,选择代理,no-resolve
  - IP-CIDR,200.32.57.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.0.0/22,选择代理,no-resolve
  - IP-CIDR,203.135.4.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.8.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.11.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.13.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.20.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.22.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.24.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.26.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.29.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.33.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.38.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.40.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.43.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.48.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.50.0/24,选择代理,no-resolve
  - IP-CIDR,42.186.0.0/16,选择代理,no-resolve
  - IP-CIDR,45.127.128.0/22,选择代理,no-resolve
  - IP-CIDR,45.195.24.0/24,选择代理,no-resolve
  - IP-CIDR,45.253.132.0/22,选择代理,no-resolve
  - IP-CIDR,45.253.240.0/22,选择代理,no-resolve
  - IP-CIDR,45.254.48.0/23,选择代理,no-resolve
  - IP-CIDR,59.111.0.0/20,选择代理,no-resolve
  - IP-CIDR,59.111.128.0/17,选择代理,no-resolve
  - IP-CIDR,103.71.120.0/21,选择代理,no-resolve
  - IP-CIDR,103.71.128.0/22,选择代理,no-resolve
  - IP-CIDR,103.71.196.0/22,选择代理,no-resolve
  - IP-CIDR,103.71.200.0/22,选择代理,no-resolve
  - IP-CIDR,103.72.12.0/22,选择代理,no-resolve
  - IP-CIDR,103.72.18.0/23,选择代理,no-resolve
  - IP-CIDR,103.72.24.0/22,选择代理,no-resolve
  - IP-CIDR,103.72.28.0/23,选择代理,no-resolve
  - IP-CIDR,103.72.38.0/23,选择代理,no-resolve
  - IP-CIDR,103.72.40.0/23,选择代理,no-resolve
  - IP-CIDR,103.72.44.0/22,选择代理,no-resolve
  - IP-CIDR,103.72.48.0/21,选择代理,no-resolve
  - IP-CIDR,103.72.128.0/21,选择代理,no-resolve
  - IP-CIDR,103.74.24.0/21,选择代理,no-resolve
  - IP-CIDR,103.74.48.0/22,选择代理,no-resolve
  - IP-CIDR,103.126.92.0/22,选择代理,no-resolve
  - IP-CIDR,103.129.252.0/22,选择代理,no-resolve
  - IP-CIDR,103.131.252.0/22,选择代理,no-resolve
  - IP-CIDR,103.135.240.0/22,选择代理,no-resolve
  - IP-CIDR,103.196.64.0/22,选择代理,no-resolve
  - IP-CIDR,106.2.32.0/19,选择代理,no-resolve
  - IP-CIDR,106.2.64.0/18,选择代理,no-resolve
  - IP-CIDR,114.113.196.0/22,选择代理,no-resolve
  - IP-CIDR,114.113.200.0/22,选择代理,no-resolve
  - IP-CIDR,115.236.112.0/20,选择代理,no-resolve
  - IP-CIDR,115.238.76.0/22,选择代理,no-resolve
  - IP-CIDR,123.58.160.0/19,选择代理,no-resolve
  - IP-CIDR,223.252.192.0/19,选择代理,no-resolve
  - IP-CIDR,101.198.128.0/18,选择代理,no-resolve
  - IP-CIDR,101.198.192.0/19,选择代理,no-resolve
  - IP-CIDR,101.199.196.0/22,选择代理,no-resolve
  - DOMAIN,p-bstarstatic.akamaized.net,📺哔哩哔哩
  - DOMAIN,p.bstarstatic.com,📺哔哩哔哩
  - DOMAIN,upos-bstar-mirrorakam.akamaized.net,📺哔哩哔哩
  - DOMAIN,upos-bstar1-mirrorakam.akamaized.net,📺哔哩哔哩
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,📺哔哩哔哩
  - DOMAIN-SUFFIX,acgvideo.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.tv,📺哔哩哔哩
  - IP-CIDR,45.43.32.234/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,103.151.150.0/23,📺哔哩哔哩,no-resolve
  - IP-CIDR,119.29.29.29/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,128.1.62.200/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,128.1.62.201/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,150.116.92.250/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,164.52.33.178/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,164.52.33.182/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,164.52.76.18/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,203.107.1.33/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,203.107.1.34/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,203.107.1.65/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,203.107.1.66/32,📺哔哩哔哩,no-resolve
  - DOMAIN,apiintl.biliapi.net,📺哔哩哔哩
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,📺哔哩哔哩
  - DOMAIN-SUFFIX,acg.tv,📺哔哩哔哩
  - DOMAIN-SUFFIX,acgvideo.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,b23.tv,📺哔哩哔哩
  - DOMAIN-SUFFIX,bigfun.cn,📺哔哩哔哩
  - DOMAIN-SUFFIX,bigfunapp.cn,📺哔哩哔哩
  - DOMAIN-SUFFIX,biliapi.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,biliapi.net,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.co,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.tv,📺哔哩哔哩
  - DOMAIN-SUFFIX,biligame.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,biligame.net,📺哔哩哔哩
  - DOMAIN-SUFFIX,biliintl.co,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilivideo.cn,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilivideo.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,hdslb.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,im9.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,smtcdns.net,📺哔哩哔哩
  - GEOIP,CN,DIRECT
  - MATCH,选择代理`
}
	
function getsbConfig(userID, hostName) {
return `{
	  "log": {
		"disabled": false,
		"level": "info",
		"timestamp": true
	  },
	  "experimental": {
		"clash_api": {
		  "external_controller": "127.0.0.1:9090",
		  "external_ui": "ui",
		  "external_ui_download_url": "",
		  "external_ui_download_detour": "",
		  "secret": "",
		  "default_mode": "Rule"
		},
		"cache_file": {
		  "enabled": true,
		  "path": "cache.db",
		  "store_fakeip": true
		}
	  },
	  "dns": {
		"servers": [
		  {
			"tag": "proxydns",
			"address": "tls://8.8.8.8/dns-query",
			"detour": "select"
		  },
		  {
			"tag": "localdns",
			"address": "h3://223.5.5.5/dns-query",
			"detour": "direct"
		  },
		  {
			"address": "rcode://refused",
			"tag": "block"
		  },
		  {
			"tag": "dns_fakeip",
			"address": "fakeip"
		  }
		],
		"rules": [
		  {
			"outbound": "any",
			"server": "localdns",
			"disable_cache": true
		  },
		  {
			"clash_mode": "Global",
			"server": "proxydns"
		  },
		  {
			"clash_mode": "Direct",
			"server": "localdns"
		  },
		  {
			"rule_set": "geosite-cn",
			"server": "localdns"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"server": "proxydns"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"query_type": [
			  "A",
			  "AAAA"
			],
			"server": "dns_fakeip"
		  }
		],
		"fakeip": {
		  "enabled": true,
		  "inet4_range": "198.18.0.0/15",
		  "inet6_range": "fc00::/18"
		},
		"independent_cache": true,
		"final": "proxydns"
	  },
	  "inbounds": [
		{
		  "type": "tun",
		  "inet4_address": "172.19.0.1/30",
		  "inet6_address": "fd00::1/126",
		  "auto_route": true,
		  "strict_route": true,
		  "sniff": true,
		  "sniff_override_destination": true,
		  "domain_strategy": "prefer_ipv4"
		}
	  ],
	  "outbounds": [
		{
		  "tag": "select",
		  "type": "selector",
		  "default": "auto",
		  "outbounds": [
			"auto",
			"CF_V1_${IP1}_${PT1}",
			"CF_V2_${IP2}_${PT2}",
			"CF_V3_${IP3}_${PT3}",
			"CF_V4_${IP4}_${PT4}",
			"CF_V5_${IP5}_${PT5}",
			"CF_V6_${IP6}_${PT6}",
			"CF_V7_${IP7}_${PT7}",
			"CF_V8_${IP8}_${PT8}",
			"CF_V9_${IP9}_${PT9}",
			"CF_V10_${IP10}_${PT10}",
			"CF_V11_${IP11}_${PT11}",
			"CF_V12_${IP12}_${PT12}",
			"CF_V13_${IP13}_${PT13}"
		  ]
		},
		{
		  "server": "${IP1}",
		  "server_port": ${PT1},
		  "tag": "CF_V1_${IP1}_${PT1}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP2}",
		  "server_port": ${PT2},
		  "tag": "CF_V2_${IP2}_${PT2}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP3}",
		  "server_port": ${PT3},
		  "tag": "CF_V3_${IP3}_${PT3}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP4}",
		  "server_port": ${PT4},
		  "tag": "CF_V4_${IP4}_${PT4}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP5}",
		  "server_port": ${PT5},
		  "tag": "CF_V5_${IP5}_${PT5}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP6}",
		  "server_port": ${PT6},
		  "tag": "CF_V6_${IP6}_${PT6}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP7}",
		  "server_port": ${PT7},
		  "tag": "CF_V7_${IP7}_${PT7}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{     
		  "server": "${IP8}",
		  "server_port": ${PT8},
		  "tag": "CF_V8_${IP8}_${PT8}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP9}",
		  "server_port": ${PT9},
		  "tag": "CF_V9_${IP9}_${PT9}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP10}",
		  "server_port": ${PT10},
		  "tag": "CF_V10_${IP10}_${PT10}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP11}",
		  "server_port": ${PT11},
		  "tag": "CF_V11_${IP11}_${PT11}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP12}",
		  "server_port": ${PT12},
		  "tag": "CF_V12_${IP12}_${PT12}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP13}",
		  "server_port": ${PT13},
		  "tag": "CF_V13_${IP13}_${PT13}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "tag": "direct",
		  "type": "direct"
		},
		{
		  "tag": "block",
		  "type": "block"
		},
		{
		  "tag": "dns-out",
		  "type": "dns"
		},
		{
		  "tag": "auto",
		  "type": "urltest",
		  "outbounds": [
			"CF_V1_${IP1}_${PT1}",
			"CF_V2_${IP2}_${PT2}",
			"CF_V3_${IP3}_${PT3}",
			"CF_V4_${IP4}_${PT4}",
			"CF_V5_${IP5}_${PT5}",
			"CF_V6_${IP6}_${PT6}",
			"CF_V7_${IP7}_${PT7}",
			"CF_V8_${IP8}_${PT8}",
			"CF_V9_${IP9}_${PT9}",
			"CF_V10_${IP10}_${PT10}",
			"CF_V11_${IP11}_${PT11}",
			"CF_V12_${IP12}_${PT12}",
			"CF_V13_${IP13}_${PT13}"
		  ],
		  "url": "https://www.gstatic.com/generate_204",
		  "interval": "1m",
		  "tolerance": 50,
		  "interrupt_exist_connections": false
		}
	  ],
	  "route": {
		"rule_set": [
		  {
			"tag": "geosite-geolocation-!cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  },
		  {
			"tag": "geosite-cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  },
		  {
			"tag": "geoip-cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  }
		],
		"auto_detect_interface": true,
		"final": "select",
		"rules": [
		  {
			"outbound": "dns-out",
			"protocol": "dns"
		  },
		  {
			"clash_mode": "Direct",
			"outbound": "direct"
		  },
		  {
			"clash_mode": "Global",
			"outbound": "select"
		  },
		  {
			"rule_set": "geoip-cn",
			"outbound": "direct"
		  },
		  {
			"rule_set": "geosite-cn",
			"outbound": "direct"
		  },
		  {
			"ip_is_private": true,
			"outbound": "direct"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"outbound": "select"
		  }
		]
	  },
	  "ntp": {
		"enabled": true,
		"server": "time.apple.com",
		"server_port": 123,
		"interval": "30m",
		"detour": "direct"
	  }
	}`
}

function getptyConfig(userID, hostName) {
	const vlessshare = btoa(`vless\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);	
		return `${vlessshare}`
	}
	
function getpclConfig(userID, hostName) {
return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🛑 全球拦截
  type: select
  proxies:
    - REJECT
    - DIRECT

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 📺哔哩哔哩
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - DOMAIN-SUFFIX,acl4.ssr,选择代理
  - DOMAIN-SUFFIX,ip6-localhost,选择代理
  - DOMAIN-SUFFIX,ip6-loopback,选择代理
  - DOMAIN-SUFFIX,lan,选择代理
  - DOMAIN-SUFFIX,local,选择代理
  - DOMAIN-SUFFIX,localhost,选择代理
  - IP-CIDR,0.0.0.0/8,选择代理,no-resolve
  - IP-CIDR,10.0.0.0/8,选择代理,no-resolve
  - IP-CIDR,100.64.0.0/10,选择代理,no-resolve
  - IP-CIDR,127.0.0.0/8,选择代理,no-resolve
  - IP-CIDR,172.16.0.0/12,选择代理,no-resolve
  - IP-CIDR,192.168.0.0/16,选择代理,no-resolve
  - IP-CIDR,198.18.0.0/16,选择代理,no-resolve
  - IP-CIDR,224.0.0.0/4,选择代理,no-resolve
  - IP-CIDR6,::1/128,选择代理,no-resolve
  - IP-CIDR6,fc00::/7,选择代理,no-resolve
  - IP-CIDR6,fe80::/10,选择代理,no-resolve
  - IP-CIDR6,fd00::/8,选择代理,no-resolve
  - DOMAIN,instant.arubanetworks.com,选择代理
  - DOMAIN,setmeup.arubanetworks.com,选择代理
  - DOMAIN,router.asus.com,选择代理
  - DOMAIN,www.asusrouter.com,选择代理
  - DOMAIN-SUFFIX,hiwifi.com,选择代理
  - DOMAIN-SUFFIX,leike.cc,选择代理
  - DOMAIN-SUFFIX,miwifi.com,选择代理
  - DOMAIN-SUFFIX,my.router,选择代理
  - DOMAIN-SUFFIX,p.to,选择代理
  - DOMAIN-SUFFIX,peiluyou.com,选择代理
  - DOMAIN-SUFFIX,phicomm.me,选择代理
  - DOMAIN-SUFFIX,router.ctc,选择代理
  - DOMAIN-SUFFIX,routerlogin.com,选择代理
  - DOMAIN-SUFFIX,tendawifi.com,选择代理
  - DOMAIN-SUFFIX,zte.home,选择代理
  - DOMAIN-SUFFIX,tplogin.cn,选择代理
  - DOMAIN-SUFFIX,wifi.cmcc,选择代理
  - DOMAIN-SUFFIX,ol.epicgames.com,选择代理
  - DOMAIN-SUFFIX,dizhensubao.getui.com,选择代理
  - DOMAIN,dl.google.com,选择代理
  - DOMAIN-SUFFIX,googletraveladservices.com,选择代理
  - DOMAIN-SUFFIX,tracking-protection.cdn.mozilla.net,选择代理
  - DOMAIN,origin-a.akamaihd.net,选择代理
  - DOMAIN,fairplay.l.qq.com,选择代理
  - DOMAIN,livew.l.qq.com,选择代理
  - DOMAIN,vd.l.qq.com,选择代理
  - DOMAIN,errlog.umeng.com,选择代理
  - DOMAIN,msg.umeng.com,选择代理
  - DOMAIN,msg.umengcloud.com,选择代理
  - DOMAIN,tracking.miui.com,选择代理
  - DOMAIN,app.adjust.com,选择代理
  - DOMAIN,bdtj.tagtic.cn,选择代理
  - DOMAIN,rewards.hypixel.net,选择代理
  - DOMAIN-SUFFIX,koodomobile.com,选择代理
  - DOMAIN-SUFFIX,koodomobile.ca,选择代理
  - DOMAIN-KEYWORD,admarvel,🛑 全球拦截
  - DOMAIN-KEYWORD,admaster,🛑 全球拦截
  - DOMAIN-KEYWORD,adsage,🛑 全球拦截
  - DOMAIN-KEYWORD,adsensor,🛑 全球拦截
  - DOMAIN-KEYWORD,adsmogo,🛑 全球拦截
  - DOMAIN-KEYWORD,adsrvmedia,🛑 全球拦截
  - DOMAIN-KEYWORD,adsserving,🛑 全球拦截
  - DOMAIN-KEYWORD,adsystem,🛑 全球拦截
  - DOMAIN-KEYWORD,adwords,🛑 全球拦截
  - DOMAIN-KEYWORD,applovin,🛑 全球拦截
  - DOMAIN-KEYWORD,appsflyer,🛑 全球拦截
  - DOMAIN-KEYWORD,domob,🛑 全球拦截
  - DOMAIN-KEYWORD,duomeng,🛑 全球拦截
  - DOMAIN-KEYWORD,dwtrack,🛑 全球拦截
  - DOMAIN-KEYWORD,guanggao,🛑 全球拦截
  - DOMAIN-KEYWORD,omgmta,🛑 全球拦截
  - DOMAIN-KEYWORD,omniture,🛑 全球拦截
  - DOMAIN-KEYWORD,openx,🛑 全球拦截
  - DOMAIN-KEYWORD,partnerad,🛑 全球拦截
  - DOMAIN-KEYWORD,pingfore,🛑 全球拦截
  - DOMAIN-KEYWORD,socdm,🛑 全球拦截
  - DOMAIN-KEYWORD,supersonicads,🛑 全球拦截
  - DOMAIN-KEYWORD,wlmonitor,🛑 全球拦截
  - DOMAIN-KEYWORD,zjtoolbar,🛑 全球拦截
  - DOMAIN-SUFFIX,09mk.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,100peng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,114la.com,🛑 全球拦截
  - DOMAIN-SUFFIX,123juzi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,138lm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,17un.com,🛑 全球拦截
  - DOMAIN-SUFFIX,2cnt.net,🛑 全球拦截
  - DOMAIN-SUFFIX,3gmimo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,3xx.vip,🛑 全球拦截
  - DOMAIN-SUFFIX,51.la,🛑 全球拦截
  - DOMAIN-SUFFIX,51taifu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,51yes.com,🛑 全球拦截
  - DOMAIN-SUFFIX,600ad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,6dad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,70e.com,🛑 全球拦截
  - DOMAIN-SUFFIX,86.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,8le8le.com,🛑 全球拦截
  - DOMAIN-SUFFIX,8ox.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,95558000.com,🛑 全球拦截
  - DOMAIN-SUFFIX,99click.com,🛑 全球拦截
  - DOMAIN-SUFFIX,99youmeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a3p4.net,🛑 全球拦截
  - DOMAIN-SUFFIX,acs86.com,🛑 全球拦截
  - DOMAIN-SUFFIX,acxiom-online.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-brix.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-delivery.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-locus.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-plus.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad7.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adadapted.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adadvisor.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adap.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,adbana.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adchina.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adcome.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ader.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,adform.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adfuture.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adhouyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adinfuse.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adirects.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adjust.io,🛑 全球拦截
  - DOMAIN-SUFFIX,adkmob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adlive.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adlocus.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admaji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admin6.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admon.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adnyg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adpolestar.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adpro.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adpush.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adquan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adreal.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ads8.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsame.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsmogo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsmogo.org,🛑 全球拦截
  - DOMAIN-SUFFIX,adsunflower.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsunion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adtrk.me,🛑 全球拦截
  - DOMAIN-SUFFIX,adups.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aduu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,advertising.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adview.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,advmob.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adwetec.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adwhirl.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adwo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adxmi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adzerk.net,🛑 全球拦截
  - DOMAIN-SUFFIX,agrant.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,agrantsem.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aihaoduo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ajapk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,allyes.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,allyes.com,🛑 全球拦截
  - DOMAIN-SUFFIX,amazon-adsystem.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analysys.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,angsrvr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,anquan.org,🛑 全球拦截
  - DOMAIN-SUFFIX,anysdk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appadhoc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appboy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appdriver.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,appjiagu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,applifier.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appsflyer.com,🛑 全球拦截
  - DOMAIN-SUFFIX,atdmt.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baifendian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,banmamedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baoyatu.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,baycode.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,bayimob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,behe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bfshan.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,biddingos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,biddingx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bjvvqu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,bjxiaohua.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bloggerads.net,🛑 全球拦截
  - DOMAIN-SUFFIX,branch.io,🛑 全球拦截
  - DOMAIN-SUFFIX,bsdev.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,bshare.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,btyou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bugtags.com,🛑 全球拦截
  - DOMAIN-SUFFIX,buysellads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c0563.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cacafly.com,🛑 全球拦截
  - DOMAIN-SUFFIX,casee.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cdnmaster.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chance-ad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chanet.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,chartbeat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chartboost.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chengadx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,chmae.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clickadu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clicki.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,clicktracks.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clickzs.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cloudmobi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,cmcore.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cnxad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cnzz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cnzzlink.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cocounion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,coocaatv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cooguo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,coolguang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,coremetrics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpmchina.co,🛑 全球拦截
  - DOMAIN-SUFFIX,cpx24.com,🛑 全球拦截
  - DOMAIN-SUFFIX,crasheye.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,crosschannel.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ctrmi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,customer-security.online,🛑 全球拦截
  - DOMAIN-SUFFIX,daoyoudao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,datouniao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ddapp.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dianjoy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dianru.com,🛑 全球拦截
  - DOMAIN-SUFFIX,disqusads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,domob.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,domob.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,domob.org,🛑 全球拦截
  - DOMAIN-SUFFIX,dotmore.com.tw,🛑 全球拦截
  - DOMAIN-SUFFIX,doubleverify.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doudouguo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doumob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,duanat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,duiba.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,duomeng.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dxpmedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,edigitalsurvey.com,🛑 全球拦截
  - DOMAIN-SUFFIX,eduancm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,emarbox.com,🛑 全球拦截
  - DOMAIN-SUFFIX,exosrv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fancyapi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,feitian001.com,🛑 全球拦截
  - DOMAIN-SUFFIX,feixin2.com,🛑 全球拦截
  - DOMAIN-SUFFIX,flashtalking.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fraudmetrix.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,g1.tagtic.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gentags.net,🛑 全球拦截
  - DOMAIN-SUFFIX,gepush.com,🛑 全球拦截
  - DOMAIN-SUFFIX,getui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,glispa.com,🛑 全球拦截
  - DOMAIN-SUFFIX,go-mpulse,🛑 全球拦截
  - DOMAIN-SUFFIX,go-mpulse.net,🛑 全球拦截
  - DOMAIN-SUFFIX,godloveme.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gridsum.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gridsumdissector.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gridsumdissector.com,🛑 全球拦截
  - DOMAIN-SUFFIX,growingio.com,🛑 全球拦截
  - DOMAIN-SUFFIX,guohead.com,🛑 全球拦截
  - DOMAIN-SUFFIX,guomob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,haoghost.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hivecn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hypers.com,🛑 全球拦截
  - DOMAIN-SUFFIX,icast.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,igexin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,il8r.com,🛑 全球拦截
  - DOMAIN-SUFFIX,imageter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,immob.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,inad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobi.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobicdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobicdn.net,🛑 全球拦截
  - DOMAIN-SUFFIX,innity.com,🛑 全球拦截
  - DOMAIN-SUFFIX,instabug.com,🛑 全球拦截
  - DOMAIN-SUFFIX,intely.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,iperceptions.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ipinyou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,irs01.com,🛑 全球拦截
  - DOMAIN-SUFFIX,irs01.net,🛑 全球拦截
  - DOMAIN-SUFFIX,irs09.com,🛑 全球拦截
  - DOMAIN-SUFFIX,istreamsche.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jesgoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jiaeasy.net,🛑 全球拦截
  - DOMAIN-SUFFIX,jiguang.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jimdo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jisucn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jmgehn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jpush.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jusha.com,🛑 全球拦截
  - DOMAIN-SUFFIX,juzi.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,juzilm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kejet.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kejet.net,🛑 全球拦截
  - DOMAIN-SUFFIX,keydot.net,🛑 全球拦截
  - DOMAIN-SUFFIX,keyrun.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,kmd365.com,🛑 全球拦截
  - DOMAIN-SUFFIX,krux.net,🛑 全球拦截
  - DOMAIN-SUFFIX,lnk0.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lnk8.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,localytics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lomark.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,lotuseed.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lrswl.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lufax.com,🛑 全球拦截
  - DOMAIN-SUFFIX,madhouse.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,madmini.com,🛑 全球拦截
  - DOMAIN-SUFFIX,madserving.com,🛑 全球拦截
  - DOMAIN-SUFFIX,magicwindow.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mathtag.com,🛑 全球拦截
  - DOMAIN-SUFFIX,maysunmedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mbai.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mediaplex.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mediav.com,🛑 全球拦截
  - DOMAIN-SUFFIX,megajoy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mgogo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,miaozhen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,microad-cn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,miidi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,mijifen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mixpanel.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mjmobi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mng-ads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,moad.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,moatads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobaders.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobclix.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobgi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobisage.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobvista.com,🛑 全球拦截
  - DOMAIN-SUFFIX,moogos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mopub.com,🛑 全球拦截
  - DOMAIN-SUFFIX,moquanad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mpush.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mxpnl.com,🛑 全球拦截
  - DOMAIN-SUFFIX,myhug.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mzy2014.com,🛑 全球拦截
  - DOMAIN-SUFFIX,networkbench.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ninebox.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ntalker.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nylalobghyhirgh.com,🛑 全球拦截
  - DOMAIN-SUFFIX,o2omobi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,oadz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,oneapm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,onetad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,optaim.com,🛑 全球拦截
  - DOMAIN-SUFFIX,optimix.asia,🛑 全球拦截
  - DOMAIN-SUFFIX,optimix.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,optimizelyapis.com,🛑 全球拦截
  - DOMAIN-SUFFIX,overture.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p0y.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pagechoice.net,🛑 全球拦截
  - DOMAIN-SUFFIX,pingdom.net,🛑 全球拦截
  - DOMAIN-SUFFIX,plugrush.com,🛑 全球拦截
  - DOMAIN-SUFFIX,popin.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,pro.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,publicidad.net,🛑 全球拦截
  - DOMAIN-SUFFIX,publicidad.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,pubmatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pubnub.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qcl777.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qiyou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qtmojo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,quantcount.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qucaigg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qumi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qxxys.com,🛑 全球拦截
  - DOMAIN-SUFFIX,reachmax.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,responsys.net,🛑 全球拦截
  - DOMAIN-SUFFIX,revsci.net,🛑 全球拦截
  - DOMAIN-SUFFIX,rlcdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rtbasia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sanya1.com,🛑 全球拦截
  - DOMAIN-SUFFIX,scupio.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shuiguo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shuzilm.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,similarweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sitemeter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sitescout.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sitetag.us,🛑 全球拦截
  - DOMAIN-SUFFIX,smartmad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,social-touch.com,🛑 全球拦截
  - DOMAIN-SUFFIX,somecoding.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sponsorpay.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stargame.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stg8.com,🛑 全球拦截
  - DOMAIN-SUFFIX,switchadhub.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sycbbs.com,🛑 全球拦截
  - DOMAIN-SUFFIX,synacast.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sysdig.com,🛑 全球拦截
  - DOMAIN-SUFFIX,talkingdata.com,🛑 全球拦截
  - DOMAIN-SUFFIX,talkingdata.net,🛑 全球拦截
  - DOMAIN-SUFFIX,tansuotv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tanv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tanx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tapjoy.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,th7.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,thoughtleadr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tianmidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tiqcdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,touclick.com,🛑 全球拦截
  - DOMAIN-SUFFIX,trafficjam.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,trafficmp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tuia.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ueadlian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uerzyr.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ugdtimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ugvip.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ujian.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,ukeiae.com,🛑 全球拦截
  - DOMAIN-SUFFIX,umeng.co,🛑 全球拦截
  - DOMAIN-SUFFIX,umeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,umtrack.com,🛑 全球拦截
  - DOMAIN-SUFFIX,unimhk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union-wifi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union001.com,🛑 全球拦截
  - DOMAIN-SUFFIX,unionsy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,unlitui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uri6.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ushaqi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,usingde.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uuzu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uyunad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vamaker.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vlion.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,voiceads.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,voiceads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vpon.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vungle.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,vungle.com,🛑 全球拦截
  - DOMAIN-SUFFIX,waps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wapx.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,webterren.com,🛑 全球拦截
  - DOMAIN-SUFFIX,whpxy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,winads.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,winasdaq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wiyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wooboo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wqmobile.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wrating.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wumii.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wwads.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,xcy8.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xdrig.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xiaozhen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xibao100.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xtgreat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yandui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yigao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yijifen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yinooo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yiqifa.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yiwk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ylunion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ymapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ymcdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,yongyuelm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yooli.com,🛑 全球拦截
  - DOMAIN-SUFFIX,youmi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,youxiaoad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yoyi.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,yoyi.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,yrxmr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ysjwj.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yunjiasu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yunpifu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zampdsp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zamplus.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zcdsp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zhidian3g.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zhiziyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zhjfad.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zqzxz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zzsx8.com,🛑 全球拦截
  - DOMAIN-SUFFIX,acuityplatform.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-stir.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-survey.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad4game.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adcloud.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,adcolony.com,🛑 全球拦截
  - DOMAIN-SUFFIX,addthis.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adfurikun.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,adhigh.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adhood.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adinall.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adition.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adk2x.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admarket.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,admarvel.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adnxs.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adotmob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adperium.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adriver.ru,🛑 全球拦截
  - DOMAIN-SUFFIX,adroll.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsco.re,🛑 全球拦截
  - DOMAIN-SUFFIX,adservice.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsrvr.org,🛑 全球拦截
  - DOMAIN-SUFFIX,adsymptotic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adtaily.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adtech.de,🛑 全球拦截
  - DOMAIN-SUFFIX,adtechjp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adtechus.com,🛑 全球拦截
  - DOMAIN-SUFFIX,airpush.com,🛑 全球拦截
  - DOMAIN-SUFFIX,am15.net,🛑 全球拦截
  - DOMAIN-SUFFIX,amobee.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appier.net,🛑 全球拦截
  - DOMAIN-SUFFIX,applift.com,🛑 全球拦截
  - DOMAIN-SUFFIX,apsalar.com,🛑 全球拦截
  - DOMAIN-SUFFIX,atas.io,🛑 全球拦截
  - DOMAIN-SUFFIX,awempire.com,🛑 全球拦截
  - DOMAIN-SUFFIX,axonix.com,🛑 全球拦截
  - DOMAIN-SUFFIX,beintoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bepolite.eu,🛑 全球拦截
  - DOMAIN-SUFFIX,bidtheatre.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bidvertiser.com,🛑 全球拦截
  - DOMAIN-SUFFIX,blismedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,brucelead.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bttrack.com,🛑 全球拦截
  - DOMAIN-SUFFIX,casalemedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,celtra.com,🛑 全球拦截
  - DOMAIN-SUFFIX,channeladvisor.com,🛑 全球拦截
  - DOMAIN-SUFFIX,connexity.net,🛑 全球拦截
  - DOMAIN-SUFFIX,criteo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,criteo.net,🛑 全球拦截
  - DOMAIN-SUFFIX,csbew.com,🛑 全球拦截
  - DOMAIN-SUFFIX,directrev.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dumedia.ru,🛑 全球拦截
  - DOMAIN-SUFFIX,effectivemeasure.com,🛑 全球拦截
  - DOMAIN-SUFFIX,effectivemeasure.net,🛑 全球拦截
  - DOMAIN-SUFFIX,eqads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,everesttech.net,🛑 全球拦截
  - DOMAIN-SUFFIX,exoclick.com,🛑 全球拦截
  - DOMAIN-SUFFIX,extend.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,eyereturn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fastapi.net,🛑 全球拦截
  - DOMAIN-SUFFIX,fastclick.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fastclick.net,🛑 全球拦截
  - DOMAIN-SUFFIX,flurry.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gosquared.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gtags.net,🛑 全球拦截
  - DOMAIN-SUFFIX,heyzap.com,🛑 全球拦截
  - DOMAIN-SUFFIX,histats.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hitslink.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hot-mob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hyperpromote.com,🛑 全球拦截
  - DOMAIN-SUFFIX,i-mobile.co.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,imrworldwide.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inmobi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inner-active.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,intentiq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inter1ads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ipredictive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ironsrc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iskyworker.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jizzads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,juicyads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kochava.com,🛑 全球拦截
  - DOMAIN-SUFFIX,leadbolt.com,🛑 全球拦截
  - DOMAIN-SUFFIX,leadbolt.net,🛑 全球拦截
  - DOMAIN-SUFFIX,leadboltads.net,🛑 全球拦截
  - DOMAIN-SUFFIX,leadboltapps.net,🛑 全球拦截
  - DOMAIN-SUFFIX,leadboltmobile.net,🛑 全球拦截
  - DOMAIN-SUFFIX,lenzmx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,liveadvert.com,🛑 全球拦截
  - DOMAIN-SUFFIX,marketgid.com,🛑 全球拦截
  - DOMAIN-SUFFIX,marketo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mdotm.com,🛑 全球拦截
  - DOMAIN-SUFFIX,medialytics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,medialytics.io,🛑 全球拦截
  - DOMAIN-SUFFIX,meetrics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,meetrics.net,🛑 全球拦截
  - DOMAIN-SUFFIX,mgid.com,🛑 全球拦截
  - DOMAIN-SUFFIX,millennialmedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobadme.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,mobfox.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobileadtrading.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobilityware.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mojiva.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mookie1.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msads.net,🛑 全球拦截
  - DOMAIN-SUFFIX,mydas.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,nend.net,🛑 全球拦截
  - DOMAIN-SUFFIX,netshelter.net,🛑 全球拦截
  - DOMAIN-SUFFIX,nexage.com,🛑 全球拦截
  - DOMAIN-SUFFIX,owneriq.net,🛑 全球拦截
  - DOMAIN-SUFFIX,pixels.asia,🛑 全球拦截
  - DOMAIN-SUFFIX,plista.com,🛑 全球拦截
  - DOMAIN-SUFFIX,popads.net,🛑 全球拦截
  - DOMAIN-SUFFIX,powerlinks.com,🛑 全球拦截
  - DOMAIN-SUFFIX,propellerads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,quantserve.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rayjump.com,🛑 全球拦截
  - DOMAIN-SUFFIX,revdepo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rubiconproject.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sape.ru,🛑 全球拦截
  - DOMAIN-SUFFIX,scorecardresearch.com,🛑 全球拦截
  - DOMAIN-SUFFIX,segment.com,🛑 全球拦截
  - DOMAIN-SUFFIX,serving-sys.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sharethis.com,🛑 全球拦截
  - DOMAIN-SUFFIX,smaato.com,🛑 全球拦截
  - DOMAIN-SUFFIX,smaato.net,🛑 全球拦截
  - DOMAIN-SUFFIX,smartadserver.com,🛑 全球拦截
  - DOMAIN-SUFFIX,smartnews-ads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,startapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,startappexchange.com,🛑 全球拦截
  - DOMAIN-SUFFIX,statcounter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,steelhousemedia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stickyadstv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,supersonic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,taboola.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tapjoy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tapjoyads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,trafficjunky.com,🛑 全球拦截
  - DOMAIN-SUFFIX,trafficjunky.net,🛑 全球拦截
  - DOMAIN-SUFFIX,tribalfusion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,turn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uberads.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vidoomy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,viglink.com,🛑 全球拦截
  - DOMAIN-SUFFIX,voicefive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wedolook.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yadro.ru,🛑 全球拦截
  - DOMAIN-SUFFIX,yengo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zedo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zemanta.com,🛑 全球拦截
  - DOMAIN-SUFFIX,11h5.com,🛑 全球拦截
  - DOMAIN-SUFFIX,1kxun.mobi,🛑 全球拦截
  - DOMAIN-SUFFIX,26zsd.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,519397.com,🛑 全球拦截
  - DOMAIN-SUFFIX,626uc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,915.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appget.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,appuu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,coinhive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,huodonghezi.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,vcbn65.xyz,🛑 全球拦截
  - DOMAIN-SUFFIX,wanfeng1.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wep016.top,🛑 全球拦截
  - DOMAIN-SUFFIX,win-stock.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zantainet.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dh54wf.xyz,🛑 全球拦截
  - DOMAIN-SUFFIX,g2q3e.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,114so.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,go.10086.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hivedata.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,navi.gd.chinamobile.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adgeo.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.126.net,🛑 全球拦截
  - DOMAIN-SUFFIX,bobo.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clkservice.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,conv.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dsp-impr2.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dsp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fa.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g1.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gb.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gorgon.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,haitaoad.nosdn.127.net,🛑 全球拦截
  - DOMAIN-SUFFIX,iadmatvideo.nosdn.127.net,🛑 全球拦截
  - DOMAIN-SUFFIX,img1.126.net,🛑 全球拦截
  - DOMAIN-SUFFIX,img2.126.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ir.mail.126.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ir.mail.yeah.net,🛑 全球拦截
  - DOMAIN-SUFFIX,mimg.126.net,🛑 全球拦截
  - DOMAIN-SUFFIX,nc004x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nc045x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nex.corp.163.com,🛑 全球拦截
  - DOMAIN-SUFFIX,oimagea2.ydstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pagechoice.net,🛑 全球拦截
  - DOMAIN-SUFFIX,prom.gome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,qchannel0d.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,qt002x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rlogs.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,static.flv.uuzuonline.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tb060x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tb104x.corp.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wanproxy.127.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ydpushserver.youdao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cvda.17173.com,🛑 全球拦截
  - DOMAIN-SUFFIX,imgapp.yeyou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log1.17173.com,🛑 全球拦截
  - DOMAIN-SUFFIX,s.17173cdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ue.yeyoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vda.17173.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.wanmei.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gg.stargame.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,download.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,houtai.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jifen.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jifendownload.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,minipage.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zhushou.2345.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,3600.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gamebox.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jiagu.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,kuaikan.netmon.360safe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,leak.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,lianmeng.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pub.se.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,s.so.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,shouji.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,soft.data.weather.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.360safe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.m.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,update.360safe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.360.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,58.xgo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,brandshow.58.com,🛑 全球拦截
  - DOMAIN-SUFFIX,imp.xgo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,jing.58.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.xgo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,track.58.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tracklog.58.com,🛑 全球拦截
  - DOMAIN-SUFFIX,acjs.aliyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adash-c.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adash-c.ut.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adashx4yt.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adashxgc.ut.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afp.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ai.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,alipaylog.com,🛑 全球拦截
  - DOMAIN-SUFFIX,atanx.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,atanx2.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fav.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.click.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.tbcdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gma.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gtmsdd.alicdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hydra.alibaba.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pindao.huoban.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,re.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,redirect.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rj.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdkinit.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,show.re.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,simaba.m.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,simaba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,srd.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,strip.taobaocdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tns.simba.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tyh.taobao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,userimg.qunar.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yiliao.hupan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,3dns-2.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,3dns-3.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,activate-sea.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,activate-sjc0.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,activate.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adobe-dns-2.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adobe-dns-3.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adobe-dns.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ereg.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,geo2.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hl2rcv.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hlrcv.stage.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lm.licenses.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lmlicenses.wip4.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,na1r.services.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,na2m-pr.licenses.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,practivate.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wip3.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wwis-dubc1-vip60.adobe.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adserver.unityads.unity3d.com,🛑 全球拦截
  - DOMAIN-SUFFIX,33.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adproxy.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,al.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,alert.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,applogapi.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,c.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cmx.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dspmnt.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pcd.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,push.app.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pvx.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rd.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rdx.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,stats.autohome.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,a.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,a.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.duapps.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.player.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adscdn.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adscdn.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adx.xiaodutv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ae.bdstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afd.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,afd.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,als.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,als.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,anquan.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,anquan.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,antivirus.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api.mobula.sdk.duapps.com,🛑 全球拦截
  - DOMAIN-SUFFIX,appc.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,appc.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,as.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,as.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baichuan.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baidu9635.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,baidutv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,banlv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bar.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bdplus.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,btlaunch.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,c.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cb.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cb.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cbjs.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cbjs.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cbjslog.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cbjslog.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cjhq.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cjhq.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cleaner.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.bes.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.hm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.qianqian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.tieba.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro.zhidao.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro2.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cpro2.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpu-admin.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,crs.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,crs.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,datax.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl-vip.bav.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl-vip.pcfaster.baidu.co.th,🛑 全球拦截
  - DOMAIN-SUFFIX,dl.client.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl.ops.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl1sw.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl2.bav.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dlsw.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dlsw.br.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,download.bav.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,download.sd.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,drmcmm.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,drmcmm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dup.baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dxp.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dzl.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,e.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,e.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,eclick.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,eclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ecma.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ecmb.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ecmc.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,eiv.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,eiv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,em.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ers.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,f10.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fc-.cdn.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fc-feed.cdn.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fexclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gimg.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,guanjia.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hc.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hc.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hm.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hmma.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hmma.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hpd.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hpd.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,idm-su.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iebar.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ikcode.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,imageplus.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,imageplus.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,img.taotaosou.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,img01.taotaosou.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,itsdata.map.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,j.br.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kstj.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.music.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.nuomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m1.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ma.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ma.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mg09.zhaopin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mipcache.bdstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobads-logs.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobads-logs.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobads.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobads.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mpro.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mtj.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mtj.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,neirong.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nsclick.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,nsclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nsclickvideo.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,openrcv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pc.videoclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pos.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pups.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pups.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pups.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.music.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.zhanzhang.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,qchannel0d.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,qianclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,release.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,res.limei.com,🛑 全球拦截
  - DOMAIN-SUFFIX,res.mi.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rigel.baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,river.zhidao.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rj.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rj.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rp.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rp.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rplog.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,s.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sclick.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sestat.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shadu.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,share.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sobar.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sobartop.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,spcode.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,spcode.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.v.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,su.bdimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,su.bdstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tk.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,tk.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tkweb.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tob-cms.bj.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,toolbar.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tracker.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tuijian.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tuisong.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,tuisong.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ubmcmm.baidustatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ucstat.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ucstat.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ulic.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ulog.imap.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,union.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,unionimage.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,utility.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,utility.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,utk.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,utk.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,videopush.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,videopush.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vv84.bj.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,w.gdown.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,w.x.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wangmeng.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wangmeng.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,weishi.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wenku-cms.bj.bcebos.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wisepush.video.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wm.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wm.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,znsv.baidu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,znsv.baidu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zz.bdstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zzy1.quyaoya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.zhangyue.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.ps.easou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aishowbger.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api.itaoxiaoshuo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,assets.ps.easou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bbcoe.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cj.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dkeyn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,drdwy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,e.aa985.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,e.v02u9.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,e701.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ehxyz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ethod.gzgmjcx.com,🛑 全球拦截
  - DOMAIN-SUFFIX,focuscat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hdswgc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jyd.fjzdmy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.ourlj.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.txtxr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.vsxet.com,🛑 全球拦截
  - DOMAIN-SUFFIX,miam4.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,o.if.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.vq6nsu.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,picture.duokan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.zhangyue.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pyerc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,s1.cmfu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sc.shayugg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdk.cferw.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sezvc.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sys.zhangyue.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tjlog.ps.easou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tongji.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ut2.shuqistat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xgcsr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xjq.jxmqkj.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xpe.cxaerp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xtzxmy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xyrkl.com,🛑 全球拦截
  - DOMAIN-SUFFIX,zhuanfakong.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dsp.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ic.snssdk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.snssdk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nativeapp.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pangolin-sdk-toutiao-b.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pangolin-sdk-toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pangolin.snssdk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,partner.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pglstatp-toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sm.toutiao.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a.dangdang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.dangdang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,schprompt.dangdang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,t.dangdang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.duomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,boxshows.com,🛑 全球拦截
  - DOMAIN-SUFFIX,staticxx.facebook.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click1n.soufun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clickm.fang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clickn.fang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,countpvn.light.fang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,countubn.light.soufun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mshow.fang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tongji.home.soufun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,admob.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.gmodules.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adservice.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afd.l.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,badad.googleplex.com,🛑 全球拦截
  - DOMAIN-SUFFIX,csi.gstatic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doubleclick.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doubleclick.net,🛑 全球拦截
  - DOMAIN-SUFFIX,google-analytics.com,🛑 全球拦截
  - DOMAIN-SUFFIX,googleadservices.com,🛑 全球拦截
  - DOMAIN-SUFFIX,googleadsserving.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,googlecommerce.com,🛑 全球拦截
  - DOMAIN-SUFFIX,googlesyndication.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobileads.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pagead-tpc.l.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pagead.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pagead.l.google.com,🛑 全球拦截
  - DOMAIN-SUFFIX,service.urchin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.union.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c-nfa.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cps.360buy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,img-x.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jrclick.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jzt.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,policy.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.m.jd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.service.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsfile.bssdlbig.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,d.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,downmobile.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gad.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gamebox.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gcapi.sy.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gg.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,install.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,install2.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kgmobilestat.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,kuaikaiapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.stat.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.web.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,minidcsc.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mo.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobilelog.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msg.mobile.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mvads.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.mobile.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rtmonitor.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdn.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tj.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,update.mobile.kugou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,apk.shouji.koowo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,deliver.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,g.koowo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,kwmsg.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,log.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobilead.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,msclick2.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,msphoneclick.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,updatepage.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wa.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,webstat.kuwo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,aider-res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-flow.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-game.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-push.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aries.mzres.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bro.flyme.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cal.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ebook.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ebook.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game-res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,infocenter.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,openapi-news.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,reader.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,reader.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,t-e.flyme.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,t-flow.flyme.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,tongji-res1.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tongji.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,umid.orion.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,upush.res.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uxip.meizu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a.koudai.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adui.tg.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,corp.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dc.meitustat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gg.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mdc.meitustat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,meitubeauty.meitudata.com,🛑 全球拦截
  - DOMAIN-SUFFIX,message.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rabbit.meitustat.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rabbit.tg.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tuiguang.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xiuxiu.android.dl.meitu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xiuxiu.mobile.meitudata.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a.market.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad1.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adv.sec.intl.miui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adv.sec.miui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bss.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,d.g.mi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,data.mistat.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,de.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dvb.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jellyfish.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,migc.g.mi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,migcreport.g.mi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,notice.game.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ppurifier.game.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,r.browser.miui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,security.browser.miui.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shenghuo.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.pandora.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,union.mi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wtradv.market.xiaomi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.api.moji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,app.moji001.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cdn.moji002.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cdn2.moji002.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fds.api.moji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.moji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.moji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ugc.moji001.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,admgr.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,dload.qd.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,logger.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,s.qd.qingting.fm,🛑 全球拦截
  - DOMAIN-SUFFIX,s.qd.qingtingfm.com,🛑 全球拦截
  - DOMAIN-KEYWORD,omgmtaw,🛑 全球拦截
  - DOMAIN,adsmind.apdcdn.tc.qq.com,🛑 全球拦截
  - DOMAIN,adsmind.gdtimg.com,🛑 全球拦截
  - DOMAIN,adsmind.tc.qq.com,🛑 全球拦截
  - DOMAIN,pgdt.gtimg.cn,🛑 全球拦截
  - DOMAIN,pgdt.gtimg.com,🛑 全球拦截
  - DOMAIN,pgdt.ugdtimg.com,🛑 全球拦截
  - DOMAIN,splashqqlive.gtimg.com,🛑 全球拦截
  - DOMAIN,wa.gtimg.com,🛑 全球拦截
  - DOMAIN,wxsnsdy.wxs.qq.com,🛑 全球拦截
  - DOMAIN,wxsnsdythumb.wxs.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,act.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.qun.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsfile.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bugly.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,buluo.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,e.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gdt.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,monitor.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pingma.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pingtcss.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,report.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tajs.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tcss.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uu.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ebp.renren.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jebe.renren.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jebe.xnimg.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adbox.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,add.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adimg.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,alitui.weibo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,biz.weibo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,cre.dp.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dcads.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dd.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dmp.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,game.weibo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gw5.push.mcp.weibo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,leju.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,log.mix.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mobileads.dx.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,newspush.sinajs.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pay.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,sax.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,sax.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,saxd.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,sdkapp.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,sdkapp.uve.weibo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdkclick.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,slog.sina.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,trends.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,tui.weibo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,u1.img.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wax.weibo.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wbapp.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wbapp.uve.weibo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wbclick.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,wbpctips.mobile.sina.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,zymo.mps.weibo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,123.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,123.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adsence.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,amfi.gou.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,brand.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cpc.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,epro.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fair.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,files2.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,galaxy.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,golden1.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,goto.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inte.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iwan.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lu.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lu.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pb.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pd.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,theta.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wangmeng.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,applovin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,guangzhuiyuan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads-twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,scribe.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,syndication-o.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,syndication.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tellapart.com,🛑 全球拦截
  - DOMAIN-SUFFIX,urls.api.twitter.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adslot.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,api.mp.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,applog.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,client.video.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cms.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dispatcher.upmc.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,huichuan.sm.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,log.cs.pp.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,m.uczzd.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,patriot.cs.pp.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,puds.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,server.m.pp.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,track.uc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,u.uc123.com,🛑 全球拦截
  - DOMAIN-SUFFIX,u.ucfly.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uc.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ucsec.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ucsec1.ucweb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aoodoo.feng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fengbuy.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.feng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,we.tm,🛑 全球拦截
  - DOMAIN-SUFFIX,yes1.feng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.docer.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.zookingsoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bannera.kingsoft-office-service.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bole.shangshufang.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,counter.kingsoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,docerad.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,gou.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,hoplink.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ic.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,img.gou.wpscdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,info.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ios-informationplatform.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,minfo.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,mo.res.wpscdn.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,news.docer.com,🛑 全球拦截
  - DOMAIN-SUFFIX,notify.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pc.uf.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pcfg.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pixiu.shangshufang.ksosoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,rating6.kingsoft-office-service.com,🛑 全球拦截
  - DOMAIN-SUFFIX,up.wps.kingsoft.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wpsweb-dc.wps.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,c.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,cdsget.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,news-imgpb.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,wifiapidd.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,wkanc.51y5.net,🛑 全球拦截
  - DOMAIN-SUFFIX,adse.ximalaya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,linkeye.ximalaya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,location.ximalaya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xdcs-collector.ximalaya.com,🛑 全球拦截
  - DOMAIN-SUFFIX,biz5.kankan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,float.kankan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hub5btmain.sandai.net,🛑 全球拦截
  - DOMAIN-SUFFIX,hub5emu.sandai.net,🛑 全球拦截
  - DOMAIN-SUFFIX,logic.cpm.cm.kankan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,upgrade.xl9.xunlei.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.wretch.cc,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adserver.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adss.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.query.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ane.yahoo.co.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,ard.yahoo.co.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,beap-bc.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,clicks.beap.bc.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,comet.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,doubleplay-conf-yql.media.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,flurry.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gemini.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,geo.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,js-apac-ss.ysm.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,locdrop.query.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,onepush.query.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p3p.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,partnerads.ysm.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ws.progrss.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yads.yahoo.co.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,ybp.yahoo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,shrek.6.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,simba.6.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,union.6.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,logger.baofeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,xs.houyi.baofeng.net,🛑 全球拦截
  - DOMAIN-SUFFIX,dotcounter.douyutv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api.newad.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,exp.3g.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iis3g.deliver.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mfp.deliver.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stadig.ifeng.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jobsfe.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,po.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pub.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.funshion.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.m.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afp.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.uaa.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cloudpush.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cm.passport.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cupid.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,emoticon.sns.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gamecenter.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ifacelog.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mbdlog.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,meta.video.qiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msg.71.am,🛑 全球拦截
  - DOMAIN-SUFFIX,msg1.video.qiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msg2.video.qiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,paopao.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,paopaod.qiyipic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,policy.video.iqiyi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yuedu.iqiyi.com,🛑 全球拦截
  - IP-CIDR,101.227.200.0/24,🛑 全球拦截,no-resolve
  - IP-CIDR,101.227.200.11/32,🛑 全球拦截,no-resolve
  - IP-CIDR,101.227.200.28/32,🛑 全球拦截,no-resolve
  - IP-CIDR,101.227.97.240/32,🛑 全球拦截,no-resolve
  - IP-CIDR,124.192.153.42/32,🛑 全球拦截,no-resolve
  - DOMAIN-SUFFIX,gug.ku6cdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pq.stat.ku6.com,🛑 全球拦截
  - DOMAIN-SUFFIX,st.vq.ku6.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,static.ku6.com,🛑 全球拦截
  - DOMAIN-SUFFIX,1.letvlive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,2.letvlive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ark.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dc.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,fz.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,g3.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,game.letvstore.com,🛑 全球拦截
  - DOMAIN-SUFFIX,i0.letvimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,i3.letvimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,minisite.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,n.mark.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pro.hoye.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pro.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,static.app.m.letv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,da.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,da.mgtv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.v2.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p2.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,res.hunantv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,888.tv.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adnet.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aty.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,aty.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bd.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click2.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ctr.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,epro.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,epro.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,go.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,golden1.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,golden1.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hui.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inte.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inte.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,inte.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lm.tv.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lu.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pb.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.tv.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,theta.sogoucdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,um.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uranus.sogou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,uranus.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wl.hd.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,yule.sohu.com,🛑 全球拦截
  - DOMAIN-SUFFIX,afp.pplive.com,🛑 全球拦截
  - DOMAIN-SUFFIX,app.aplus.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,as.aplus.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,asimgs.pplive.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,de.as.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,jp.as.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pp2.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.pptv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,btrace.video.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dp3.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,livep.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lives.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,livew.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mcgi.v.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mdevstat.qqlive.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,omgmta1.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,rcgi.video.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,t.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,u.l.qq.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a-dxk.play.api.3g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,actives.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.api.3g.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.api.3g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.api.mobile.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.mobile.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adcontrol.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adplay.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,b.smartvideo.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,c.yes.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dev-push.m.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dl.g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dmapp.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,e.stat.ykimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gamex.mobile.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,goods.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hudong.pl.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,hz.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iwstat.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,iyes.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,l.ykimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,l.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lstat.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,lvip.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobilemsg.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,msg.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,myes.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nstat.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p-log.ykimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.l.ykimg.com,🛑 全球拦截
  - DOMAIN-SUFFIX,p.l.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,passport-log.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.m.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,r.l.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,s.p.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sdk.m.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stats.tudou.com,🛑 全球拦截
  - DOMAIN-SUFFIX,store.tv.api.3g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,store.xl.api.3g.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tdrec.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,test.ott.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,v.l.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,val.api.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,wan.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ykatr.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ykrec.youku.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ykrectab.youku.com,🛑 全球拦截
  - IP-CIDR,117.177.248.17/32,🛑 全球拦截,no-resolve
  - IP-CIDR,117.177.248.41/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.176.139/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.176.176/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.180/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.182/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.184/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.43/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.47/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.177.80/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.182.101/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.182.102/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.182.11/32,🛑 全球拦截,no-resolve
  - IP-CIDR,223.87.182.52/32,🛑 全球拦截,no-resolve
  - DOMAIN-SUFFIX,azabu-u.ac.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,couchcoaster.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,delivery.dmkt-sp.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,ehg-youtube.hitbox.com,🛑 全球拦截
  - DOMAIN-SUFFIX,nichibenren.or.jp,🛑 全球拦截
  - DOMAIN-SUFFIX,nicorette.co.kr,🛑 全球拦截
  - DOMAIN-SUFFIX,ssl-youtube.2cnt.net,🛑 全球拦截
  - DOMAIN-SUFFIX,youtube.112.2o7.net,🛑 全球拦截
  - DOMAIN-SUFFIX,youtube.2cnt.net,🛑 全球拦截
  - DOMAIN-SUFFIX,acsystem.wasu.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.cdn.tvb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.wasu.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,afp.wasu.tv,🛑 全球拦截
  - DOMAIN-SUFFIX,c.algovid.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gg.jtertp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,gridsum-vd.cntv.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,kwflvcdn.000dn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,logstat.t.sfht.com,🛑 全球拦截
  - DOMAIN-SUFFIX,match.rtbidder.net,🛑 全球拦截
  - DOMAIN-SUFFIX,n-st.vip.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pop.uusee.com,🛑 全球拦截
  - DOMAIN-SUFFIX,static.duoshuo.com,🛑 全球拦截
  - DOMAIN-SUFFIX,t.cr-nielsen.com,🛑 全球拦截
  - DOMAIN-SUFFIX,terren.cntv.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,1.win7china.com,🛑 全球拦截
  - DOMAIN-SUFFIX,168.it168.com,🛑 全球拦截
  - DOMAIN-SUFFIX,2.win7china.com,🛑 全球拦截
  - DOMAIN-SUFFIX,801.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,801.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,803.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,803.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,806.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,806.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,808.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,808.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,92x.tumblr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,a1.itc.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-channel.wikawika.xyz,🛑 全球拦截
  - DOMAIN-SUFFIX,ad-display.wikawika.xyz,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.12306.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.3.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.95306.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.caiyunapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.cctv.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.cmvideo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.csdn.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.house365.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.thepaper.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ad.unimhk.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adadmin.house365.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adhome.1fangchan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adm.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.csdn.net,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.feedly.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.genieessp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.house365.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ads.linkedin.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adshownew.it168.com,🛑 全球拦截
  - DOMAIN-SUFFIX,adv.ccb.com,🛑 全球拦截
  - DOMAIN-SUFFIX,advert.api.thejoyrun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,analytics.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-deal.kechenggezi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,api-z.weidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,app-monitor.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,bat.bing.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bd1.52che.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bd2.52che.com,🛑 全球拦截
  - DOMAIN-SUFFIX,bdj.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,bdj.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,beacon.tingyun.com,🛑 全球拦截
  - DOMAIN-SUFFIX,cdn.jiuzhilan.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.cheshi-img.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.cheshi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,click.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,click.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,client-api.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,collector.githubapp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,counter.csdn.net,🛑 全球拦截
  - DOMAIN-SUFFIX,d0.xcar.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,de.soquair.com,🛑 全球拦截
  - DOMAIN-SUFFIX,dol.tianya.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dol.tianyaui.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,dw.xcar.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,e.nexac.com,🛑 全球拦截
  - DOMAIN-SUFFIX,eq.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,exp.17wo.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,game.51yund.com,🛑 全球拦截
  - DOMAIN-SUFFIX,ganjituiguang.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,grand.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,hosting.miarroba.info,🛑 全球拦截
  - DOMAIN-SUFFIX,iadsdk.apple.com,🛑 全球拦截
  - DOMAIN-SUFFIX,image.gentags.com,🛑 全球拦截
  - DOMAIN-SUFFIX,its-dori.tumblr.com,🛑 全球拦截
  - DOMAIN-SUFFIX,log.outbrain.com,🛑 全球拦截
  - DOMAIN-SUFFIX,m.12306media.com,🛑 全球拦截
  - DOMAIN-SUFFIX,media.cheshi-img.com,🛑 全球拦截
  - DOMAIN-SUFFIX,media.cheshi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,mobile-pubt.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,mobileads.msn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,n.cosbot.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,newton-api.ele.me,🛑 全球拦截
  - DOMAIN-SUFFIX,ozone.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,pdl.gionee.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pica-juicy.picacomic.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pixel.wp.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pub.mop.com,🛑 全球拦截
  - DOMAIN-SUFFIX,push.wandoujia.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.cheshi-img.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.cheshi.com,🛑 全球拦截
  - DOMAIN-SUFFIX,pv.xcar.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,qdp.qidian.com,🛑 全球拦截
  - DOMAIN-SUFFIX,res.gwifi.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,ssp.kssws.ks-cdn.com,🛑 全球拦截
  - DOMAIN-SUFFIX,sta.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,stat.it168.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stats.chinaz.com,🛑 全球拦截
  - DOMAIN-SUFFIX,stats.developingperspective.com,🛑 全球拦截
  - DOMAIN-SUFFIX,track.hujiang.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tracker.yhd.com,🛑 全球拦截
  - DOMAIN-SUFFIX,tralog.ganji.com,🛑 全球拦截
  - DOMAIN-SUFFIX,up.qingdaonews.com,🛑 全球拦截
  - DOMAIN-SUFFIX,vaserviece.10jqka.com.cn,🛑 全球拦截
  - DOMAIN-SUFFIX,265.com,选择代理
  - DOMAIN-SUFFIX,2mdn.net,选择代理
  - DOMAIN-SUFFIX,alt1-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt2-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt3-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt4-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt5-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt6-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt7-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,alt8-mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,app-measurement.com,选择代理
  - DOMAIN-SUFFIX,cache.pack.google.com,选择代理
  - DOMAIN-SUFFIX,clickserve.dartsearch.net,选择代理
  - DOMAIN-SUFFIX,crl.pki.goog,选择代理
  - DOMAIN-SUFFIX,dl.google.com,选择代理
  - DOMAIN-SUFFIX,dl.l.google.com,选择代理
  - DOMAIN-SUFFIX,googletagmanager.com,选择代理
  - DOMAIN-SUFFIX,googletagservices.com,选择代理
  - DOMAIN-SUFFIX,gtm.oasisfeng.com,选择代理
  - DOMAIN-SUFFIX,mtalk.google.com,选择代理
  - DOMAIN-SUFFIX,ocsp.pki.goog,选择代理
  - DOMAIN-SUFFIX,recaptcha.net,选择代理
  - DOMAIN-SUFFIX,safebrowsing-cache.google.com,选择代理
  - DOMAIN-SUFFIX,settings.crashlytics.com,选择代理
  - DOMAIN-SUFFIX,ssl-google-analytics.l.google.com,选择代理
  - DOMAIN-SUFFIX,toolbarqueries.google.com,选择代理
  - DOMAIN-SUFFIX,tools.google.com,选择代理
  - DOMAIN-SUFFIX,tools.l.google.com,选择代理
  - DOMAIN-SUFFIX,www-googletagmanager.l.google.com,选择代理
  - DOMAIN,csgo.wmsj.cn,选择代理
  - DOMAIN,dl.steam.clngaa.com,选择代理
  - DOMAIN,dl.steam.ksyna.com,选择代理
  - DOMAIN,dota2.wmsj.cn,选择代理
  - DOMAIN,st.dl.bscstorage.net,选择代理
  - DOMAIN,st.dl.eccdnx.com,选择代理
  - DOMAIN,st.dl.pinyuncloud.com,选择代理
  - DOMAIN,steampipe.steamcontent.tnkjmec.com,选择代理
  - DOMAIN,steampowered.com.8686c.com,选择代理
  - DOMAIN,steamstatic.com.8686c.com,选择代理
  - DOMAIN,wmsjsteam.com,选择代理
  - DOMAIN,xz.pphimalayanrt.com,选择代理
  - DOMAIN-SUFFIX,cm.steampowered.com,选择代理
  - DOMAIN-SUFFIX,steamchina.com,选择代理
  - DOMAIN-SUFFIX,steamcontent.com,选择代理
  - DOMAIN-SUFFIX,steamusercontent.com,选择代理
  - DOMAIN-SUFFIX,t.me,选择代理
  - DOMAIN-SUFFIX,tdesktop.com,选择代理
  - DOMAIN-SUFFIX,telegra.ph,选择代理
  - DOMAIN-SUFFIX,telegram.me,选择代理
  - DOMAIN-SUFFIX,telegram.org,选择代理
  - DOMAIN-SUFFIX,telesco.pe,选择代理
  - IP-CIDR,91.108.0.0/16,选择代理,no-resolve
  - IP-CIDR,95.161.64.0/20,选择代理,no-resolve
  - IP-CIDR,109.239.140.0/24,选择代理,no-resolve
  - IP-CIDR,149.154.160.0/20,选择代理,no-resolve
  - IP-CIDR6,2001:67c:4e8::/48,选择代理,no-resolve
  - IP-CIDR6,2001:b28:f23d::/48,选择代理,no-resolve
  - IP-CIDR6,2001:b28:f23f::/48,选择代理,no-resolve
  - DOMAIN-SUFFIX,edgedatg.com,选择代理
  - DOMAIN-SUFFIX,go.com,选择代理
  - DOMAIN-KEYWORD,abematv.akamaized.net,选择代理
  - DOMAIN-SUFFIX,abema.io,选择代理
  - DOMAIN-SUFFIX,abema.tv,选择代理
  - DOMAIN-SUFFIX,ameba.jp,选择代理
  - DOMAIN-SUFFIX,hayabusa.io,选择代理
  - DOMAIN-SUFFIX,c4assets.com,选择代理
  - DOMAIN-SUFFIX,channel4.com,选择代理
  - DOMAIN-KEYWORD,avoddashs,选择代理
  - DOMAIN,atv-ps.amazon.com,选择代理
  - DOMAIN,avodmp4s3ww-a.akamaihd.net,选择代理
  - DOMAIN,d1v5ir2lpwr8os.cloudfront.net,选择代理
  - DOMAIN,d1xfray82862hr.cloudfront.net,选择代理
  - DOMAIN,d22qjgkvxw22r6.cloudfront.net,选择代理
  - DOMAIN,d25xi40x97liuc.cloudfront.net,选择代理
  - DOMAIN,d27xxe7juh1us6.cloudfront.net,选择代理
  - DOMAIN,d3196yreox78o9.cloudfront.net,选择代理
  - DOMAIN,dmqdd6hw24ucf.cloudfront.net,选择代理
  - DOMAIN,ktpx.amazon.com,选择代理
  - DOMAIN-SUFFIX,aboutamazon.com,选择代理
  - DOMAIN-SUFFIX,aiv-cdn.net,选择代理
  - DOMAIN-SUFFIX,aiv-delivery.net,选择代理
  - DOMAIN-SUFFIX,amazon.jobs,选择代理
  - DOMAIN-SUFFIX,amazontools.com,选择代理
  - DOMAIN-SUFFIX,amazontours.com,选择代理
  - DOMAIN-SUFFIX,amazonuniversity.jobs,选择代理
  - DOMAIN-SUFFIX,amazonvideo.com,选择代理
  - DOMAIN-SUFFIX,media-amazon.com,选择代理
  - DOMAIN-SUFFIX,pv-cdn.net,选择代理
  - DOMAIN-SUFFIX,seattlespheres.com,选择代理
  - DOMAIN,gspe1-ssl.ls.apple.com,选择代理
  - DOMAIN,np-edge.itunes.apple.com,选择代理
  - DOMAIN,play-edge.itunes.apple.com,选择代理
  - DOMAIN-SUFFIX,tv.apple.com,选择代理
  - DOMAIN-KEYWORD,bbcfmt,选择代理
  - DOMAIN-KEYWORD,uk-live,选择代理
  - DOMAIN,aod-dash-uk-live.akamaized.net,选择代理
  - DOMAIN,aod-hls-uk-live.akamaized.net,选择代理
  - DOMAIN,vod-dash-uk-live.akamaized.net,选择代理
  - DOMAIN,vod-thumb-uk-live.akamaized.net,选择代理
  - DOMAIN-SUFFIX,bbc.co,选择代理
  - DOMAIN-SUFFIX,bbc.co.uk,选择代理
  - DOMAIN-SUFFIX,bbc.com,选择代理
  - DOMAIN-SUFFIX,bbc.net.uk,选择代理
  - DOMAIN-SUFFIX,bbcfmt.hs.llnwd.net,选择代理
  - DOMAIN-SUFFIX,bbci.co,选择代理
  - DOMAIN-SUFFIX,bbci.co.uk,选择代理
  - DOMAIN-SUFFIX,bidi.net.uk,选择代理
  - DOMAIN,bahamut.akamaized.net,选择代理
  - DOMAIN,gamer-cds.cdn.hinet.net,选择代理
  - DOMAIN,gamer2-cds.cdn.hinet.net,选择代理
  - DOMAIN-SUFFIX,bahamut.com.tw,选择代理
  - DOMAIN-SUFFIX,gamer.com.tw,选择代理
  - DOMAIN-KEYWORD,voddazn,选择代理
  - DOMAIN,d151l6v8er5bdm.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,d151l6v8er5bdm.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,d1sgwhnao7452x.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,dazn-api.com,选择代理
  - DOMAIN-SUFFIX,dazn.com,选择代理
  - DOMAIN-SUFFIX,dazndn.com,选择代理
  - DOMAIN-SUFFIX,dcblivedazn.akamaized.net,选择代理
  - DOMAIN-SUFFIX,indazn.com,选择代理
  - DOMAIN-SUFFIX,indaznlab.com,选择代理
  - DOMAIN-SUFFIX,sentry.io,选择代理
  - DOMAIN-SUFFIX,deezer.com,选择代理
  - DOMAIN-SUFFIX,dzcdn.net,选择代理
  - DOMAIN-SUFFIX,disco-api.com,选择代理
  - DOMAIN-SUFFIX,discovery.com,选择代理
  - DOMAIN-SUFFIX,uplynk.com,选择代理
  - DOMAIN,cdn.registerdisney.go.com,选择代理
  - DOMAIN-SUFFIX,adobedtm.com,选择代理
  - DOMAIN-SUFFIX,bam.nr-data.net,选择代理
  - DOMAIN-SUFFIX,bamgrid.com,选择代理
  - DOMAIN-SUFFIX,braze.com,选择代理
  - DOMAIN-SUFFIX,cdn.optimizely.com,选择代理
  - DOMAIN-SUFFIX,cdn.registerdisney.go.com,选择代理
  - DOMAIN-SUFFIX,cws.conviva.com,选择代理
  - DOMAIN-SUFFIX,d9.flashtalking.com,选择代理
  - DOMAIN-SUFFIX,disney-plus.net,选择代理
  - DOMAIN-SUFFIX,disney-portal.my.onetrust.com,选择代理
  - DOMAIN-SUFFIX,disney.demdex.net,选择代理
  - DOMAIN-SUFFIX,disney.my.sentry.io,选择代理
  - DOMAIN-SUFFIX,disneyplus.bn5x.net,选择代理
  - DOMAIN-SUFFIX,disneyplus.com,选择代理
  - DOMAIN-SUFFIX,disneyplus.com.ssl.sc.omtrdc.net,选择代理
  - DOMAIN-SUFFIX,disneystreaming.com,选择代理
  - DOMAIN-SUFFIX,dssott.com,选择代理
  - DOMAIN-SUFFIX,execute-api.us-east-1.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,js-agent.newrelic.com,选择代理
  - DOMAIN,bcbolt446c5271-a.akamaihd.net,选择代理
  - DOMAIN,content.jwplatform.com,选择代理
  - DOMAIN,edge.api.brightcove.com,选择代理
  - DOMAIN,videos-f.jwpsrv.com,选择代理
  - DOMAIN-SUFFIX,encoretvb.com,选择代理
  - DOMAIN-SUFFIX,fox.com,选择代理
  - DOMAIN-SUFFIX,foxdcg.com,选择代理
  - DOMAIN-SUFFIX,uplynk.com,选择代理
  - DOMAIN-SUFFIX,hbo.com,选择代理
  - DOMAIN-SUFFIX,hbogo.com,选择代理
  - DOMAIN-SUFFIX,hbomax.com,选择代理
  - DOMAIN-SUFFIX,hbomaxcdn.com,选择代理
  - DOMAIN-SUFFIX,hbonow.com,选择代理
  - DOMAIN-KEYWORD,hbogoasia,选择代理
  - DOMAIN,44wilhpljf.execute-api.ap-southeast-1.amazonaws.com,选择代理
  - DOMAIN,bcbolthboa-a.akamaihd.net,选择代理
  - DOMAIN,cf-images.ap-southeast-1.prod.boltdns.net,选择代理
  - DOMAIN,dai3fd1oh325y.cloudfront.net,选择代理
  - DOMAIN,hboasia1-i.akamaihd.net,选择代理
  - DOMAIN,hboasia2-i.akamaihd.net,选择代理
  - DOMAIN,hboasia3-i.akamaihd.net,选择代理
  - DOMAIN,hboasia4-i.akamaihd.net,选择代理
  - DOMAIN,hboasia5-i.akamaihd.net,选择代理
  - DOMAIN,hboasialive.akamaized.net,选择代理
  - DOMAIN,hbogoprod-vod.akamaized.net,选择代理
  - DOMAIN,hbolb.onwardsmg.com,选择代理
  - DOMAIN,hbounify-prod.evergent.com,选择代理
  - DOMAIN,players.brightcove.net,选择代理
  - DOMAIN,s3-ap-southeast-1.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,hboasia.com,选择代理
  - DOMAIN-SUFFIX,hbogoasia.com,选择代理
  - DOMAIN-SUFFIX,hbogoasia.hk,选择代理
  - DOMAIN-SUFFIX,5itv.tv,选择代理
  - DOMAIN-SUFFIX,ocnttv.com,选择代理
  - DOMAIN-SUFFIX,cws-hulu.conviva.com,选择代理
  - DOMAIN-SUFFIX,hulu.com,选择代理
  - DOMAIN-SUFFIX,hulu.hb.omtrdc.net,选择代理
  - DOMAIN-SUFFIX,hulu.sc.omtrdc.net,选择代理
  - DOMAIN-SUFFIX,huluad.com,选择代理
  - DOMAIN-SUFFIX,huluim.com,选择代理
  - DOMAIN-SUFFIX,hulustream.com,选择代理
  - DOMAIN-SUFFIX,happyon.jp,选择代理
  - DOMAIN-SUFFIX,hjholdings.jp,选择代理
  - DOMAIN-SUFFIX,hulu.jp,选择代理
  - DOMAIN-SUFFIX,prod.hjholdings.tv,选择代理
  - DOMAIN-SUFFIX,streaks.jp,选择代理
  - DOMAIN-SUFFIX,yb.uncn.jp,选择代理
  - DOMAIN,itvpnpmobile-a.akamaihd.net,选择代理
  - DOMAIN-SUFFIX,itv.com,选择代理
  - DOMAIN-SUFFIX,itvstatic.com,选择代理
  - DOMAIN-SUFFIX,iwara.tv,选择代理
  - DOMAIN-KEYWORD,jooxweb-api,选择代理
  - DOMAIN-SUFFIX,joox.com,选择代理
  - DOMAIN-KEYWORD,japonx,选择代理
  - DOMAIN-KEYWORD,japronx,选择代理
  - DOMAIN-SUFFIX,japonx.com,选择代理
  - DOMAIN-SUFFIX,japonx.net,选择代理
  - DOMAIN-SUFFIX,japonx.tv,选择代理
  - DOMAIN-SUFFIX,japonx.vip,选择代理
  - DOMAIN-SUFFIX,japronx.com,选择代理
  - DOMAIN-SUFFIX,japronx.net,选择代理
  - DOMAIN-SUFFIX,japronx.tv,选择代理
  - DOMAIN-SUFFIX,japronx.vip,选择代理
  - DOMAIN-SUFFIX,kfs.io,选择代理
  - DOMAIN-SUFFIX,kkbox.com,选择代理
  - DOMAIN-SUFFIX,kkbox.com.tw,选择代理
  - DOMAIN,kktv-theater.kk.stream,选择代理
  - DOMAIN,theater-kktv.cdn.hinet.net,选择代理
  - DOMAIN-SUFFIX,kktv.com.tw,选择代理
  - DOMAIN-SUFFIX,kktv.me,选择代理
  - DOMAIN,litvfreemobile-hichannel.cdn.hinet.net,选择代理
  - DOMAIN-SUFFIX,litv.tv,选择代理
  - DOMAIN,d3c7rimkq79yfu.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,d3c7rimkq79yfu.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,linetv.tw,选择代理
  - DOMAIN-SUFFIX,profile.line-scdn.net,选择代理
  - DOMAIN,d349g9zuie06uo.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,channel5.com,选择代理
  - DOMAIN-SUFFIX,my5.tv,选择代理
  - DOMAIN-KEYWORD,nowtv100,选择代理
  - DOMAIN-KEYWORD,rthklive,选择代理
  - DOMAIN,mytvsuperlimited.hb.omtrdc.net,选择代理
  - DOMAIN,mytvsuperlimited.sc.omtrdc.net,选择代理
  - DOMAIN-SUFFIX,mytvsuper.com,选择代理
  - DOMAIN-SUFFIX,tvb.com,选择代理
  - DOMAIN-KEYWORD,apiproxy-device-prod-nlb-,选择代理
  - DOMAIN-KEYWORD,dualstack.apiproxy-,选择代理
  - DOMAIN-KEYWORD,netflixdnstest,选择代理
  - DOMAIN,netflix.com.edgesuite.net,选择代理
  - DOMAIN-SUFFIX,fast.com,选择代理
  - DOMAIN-SUFFIX,netflix.com,选择代理
  - DOMAIN-SUFFIX,netflix.net,选择代理
  - DOMAIN-SUFFIX,netflixdnstest0.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest1.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest2.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest3.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest4.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest5.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest6.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest7.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest8.com,选择代理
  - DOMAIN-SUFFIX,netflixdnstest9.com,选择代理
  - DOMAIN-SUFFIX,nflxext.com,选择代理
  - DOMAIN-SUFFIX,nflximg.com,选择代理
  - DOMAIN-SUFFIX,nflximg.net,选择代理
  - DOMAIN-SUFFIX,nflxso.net,选择代理
  - DOMAIN-SUFFIX,nflxvideo.net,选择代理
  - IP-CIDR,8.41.4.0/24,选择代理,no-resolve
  - IP-CIDR,23.246.0.0/18,选择代理,no-resolve
  - IP-CIDR,37.77.184.0/21,选择代理,no-resolve
  - IP-CIDR,38.72.126.0/24,选择代理,no-resolve
  - IP-CIDR,45.57.0.0/17,选择代理,no-resolve
  - IP-CIDR,64.120.128.0/17,选择代理,no-resolve
  - IP-CIDR,66.197.128.0/17,选择代理,no-resolve
  - IP-CIDR,69.53.224.0/19,选择代理,no-resolve
  - IP-CIDR,103.87.204.0/22,选择代理,no-resolve
  - IP-CIDR,108.175.32.0/20,选择代理,no-resolve
  - IP-CIDR,185.2.220.0/22,选择代理,no-resolve
  - IP-CIDR,185.9.188.0/22,选择代理,no-resolve
  - IP-CIDR,192.173.64.0/18,选择代理,no-resolve
  - IP-CIDR,198.38.96.0/19,选择代理,no-resolve
  - IP-CIDR,198.45.48.0/20,选择代理,no-resolve
  - IP-CIDR,203.75.84.0/24,选择代理,no-resolve
  - IP-CIDR,207.45.72.0/22,选择代理,no-resolve
  - IP-CIDR,208.75.76.0/22,选择代理,no-resolve
  - DOMAIN-SUFFIX,dmc.nico,选择代理
  - DOMAIN-SUFFIX,nicovideo.jp,选择代理
  - DOMAIN-SUFFIX,nimg.jp,选择代理
  - DOMAIN-KEYWORD,nivod,选择代理
  - DOMAIN-SUFFIX,biggggg.com,选择代理
  - DOMAIN-SUFFIX,mudvod.tv,选择代理
  - DOMAIN-SUFFIX,nbys.tv,选择代理
  - DOMAIN-SUFFIX,nbys1.tv,选择代理
  - DOMAIN-SUFFIX,nbyy.tv,选择代理
  - DOMAIN-SUFFIX,newpppp.com,选择代理
  - DOMAIN-SUFFIX,nivod.tv,选择代理
  - DOMAIN-SUFFIX,nivodi.tv,选择代理
  - DOMAIN-SUFFIX,nivodz.com,选择代理
  - DOMAIN-SUFFIX,vod360.net,选择代理
  - DOMAIN-KEYWORD,olevod,选择代理
  - DOMAIN-SUFFIX,haiwaikan.com,选择代理
  - DOMAIN-SUFFIX,iole.tv,选择代理
  - DOMAIN-SUFFIX,olehd.com,选择代理
  - DOMAIN-SUFFIX,olelive.com,选择代理
  - DOMAIN-SUFFIX,olevod.com,选择代理
  - DOMAIN-SUFFIX,olevod.io,选择代理
  - DOMAIN-SUFFIX,olevod.tv,选择代理
  - DOMAIN-SUFFIX,olevodtv.com,选择代理
  - DOMAIN-KEYWORD,openai,选择代理
  - DOMAIN-SUFFIX,auth0.com,选择代理
  - DOMAIN-SUFFIX,challenges.cloudflare.com,选择代理
  - DOMAIN-SUFFIX,chatgpt.com,选择代理
  - DOMAIN-SUFFIX,client-api.arkoselabs.com,选择代理
  - DOMAIN-SUFFIX,events.statsigapi.net,选择代理
  - DOMAIN-SUFFIX,featuregates.org,选择代理
  - DOMAIN-SUFFIX,identrust.com,选择代理
  - DOMAIN-SUFFIX,intercom.io,选择代理
  - DOMAIN-SUFFIX,intercomcdn.com,选择代理
  - DOMAIN-SUFFIX,oaistatic.com,选择代理
  - DOMAIN-SUFFIX,oaiusercontent.com,选择代理
  - DOMAIN-SUFFIX,openai.com,选择代理
  - DOMAIN-SUFFIX,openaiapi-site.azureedge.net,选择代理
  - DOMAIN-SUFFIX,sentry.io,选择代理
  - DOMAIN-SUFFIX,stripe.com,选择代理
  - DOMAIN-SUFFIX,pbs.org,选择代理
  - DOMAIN-SUFFIX,pandora.com,选择代理
  - DOMAIN-SUFFIX,phncdn.com,选择代理
  - DOMAIN-SUFFIX,phprcdn.com,选择代理
  - DOMAIN-SUFFIX,pornhub.com,选择代理
  - DOMAIN-SUFFIX,pornhubpremium.com,选择代理
  - DOMAIN-SUFFIX,qobuz.com,选择代理
  - DOMAIN-SUFFIX,p-cdn.us,选择代理
  - DOMAIN-SUFFIX,sndcdn.com,选择代理
  - DOMAIN-SUFFIX,soundcloud.com,选择代理
  - DOMAIN-KEYWORD,-spotify-,选择代理
  - DOMAIN-KEYWORD,spotify.com,选择代理
  - DOMAIN-SUFFIX,pscdn.co,选择代理
  - DOMAIN-SUFFIX,scdn.co,选择代理
  - DOMAIN-SUFFIX,spoti.fi,选择代理
  - DOMAIN-SUFFIX,spotify.com,选择代理
  - DOMAIN-SUFFIX,spotifycdn.com,选择代理
  - DOMAIN-SUFFIX,spotifycdn.net,选择代理
  - DOMAIN-SUFFIX,tidal-cms.s3.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,tidal.com,选择代理
  - DOMAIN-SUFFIX,tidalhifi.com,选择代理
  - DOMAIN,hamifans.emome.net,选择代理
  - DOMAIN-SUFFIX,skyking.com.tw,选择代理
  - DOMAIN-KEYWORD,tiktokcdn,选择代理
  - DOMAIN-SUFFIX,byteoversea.com,选择代理
  - DOMAIN-SUFFIX,ibytedtos.com,选择代理
  - DOMAIN-SUFFIX,ipstatp.com,选择代理
  - DOMAIN-SUFFIX,muscdn.com,选择代理
  - DOMAIN-SUFFIX,musical.ly,选择代理
  - DOMAIN-SUFFIX,tik-tokapi.com,选择代理
  - DOMAIN-SUFFIX,tiktok.com,选择代理
  - DOMAIN-SUFFIX,tiktokcdn.com,选择代理
  - DOMAIN-SUFFIX,tiktokv.com,选择代理
  - DOMAIN-KEYWORD,ttvnw,选择代理
  - DOMAIN-SUFFIX,ext-twitch.tv,选择代理
  - DOMAIN-SUFFIX,jtvnw.net,选择代理
  - DOMAIN-SUFFIX,ttvnw.net,选择代理
  - DOMAIN-SUFFIX,twitch-ext.rootonline.de,选择代理
  - DOMAIN-SUFFIX,twitch.tv,选择代理
  - DOMAIN-SUFFIX,twitchcdn.net,选择代理
  - PROCESS-NAME,com.viu.pad,选择代理
  - PROCESS-NAME,com.viu.phone,选择代理
  - PROCESS-NAME,com.vuclip.viu,选择代理
  - DOMAIN,api.viu.now.com,选择代理
  - DOMAIN,d1k2us671qcoau.cloudfront.net,选择代理
  - DOMAIN,d2anahhhmp1ffz.cloudfront.net,选择代理
  - DOMAIN,dfp6rglgjqszk.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,cognito-identity.us-east-1.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,d1k2us671qcoau.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,d2anahhhmp1ffz.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,dfp6rglgjqszk.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,mobileanalytics.us-east-1.amazonaws.com,选择代理
  - DOMAIN-SUFFIX,viu.com,选择代理
  - DOMAIN-SUFFIX,viu.now.com,选择代理
  - DOMAIN-SUFFIX,viu.tv,选择代理
  - DOMAIN-KEYWORD,youtube,选择代理
  - DOMAIN,youtubei.googleapis.com,选择代理
  - DOMAIN,yt3.ggpht.com,选择代理
  - DOMAIN-SUFFIX,googlevideo.com,选择代理
  - DOMAIN-SUFFIX,gvt2.com,选择代理
  - DOMAIN-SUFFIX,withyoutube.com,选择代理
  - DOMAIN-SUFFIX,youtu.be,选择代理
  - DOMAIN-SUFFIX,youtube-nocookie.com,选择代理
  - DOMAIN-SUFFIX,youtube.com,选择代理
  - DOMAIN-SUFFIX,youtubeeducation.com,选择代理
  - DOMAIN-SUFFIX,youtubegaming.com,选择代理
  - DOMAIN-SUFFIX,youtubekids.com,选择代理
  - DOMAIN-SUFFIX,yt.be,选择代理
  - DOMAIN-SUFFIX,ytimg.com,选择代理
  - DOMAIN,music.youtube.com,选择代理
  - DOMAIN-SUFFIX,1password.com,选择代理
  - DOMAIN-SUFFIX,adguard.org,选择代理
  - DOMAIN-SUFFIX,bit.no.com,选择代理
  - DOMAIN-SUFFIX,btlibrary.me,选择代理
  - DOMAIN-SUFFIX,cloudcone.com,选择代理
  - DOMAIN-SUFFIX,dubox.com,选择代理
  - DOMAIN-SUFFIX,gameloft.com,选择代理
  - DOMAIN-SUFFIX,garena.com,选择代理
  - DOMAIN-SUFFIX,hoyolab.com,选择代理
  - DOMAIN-SUFFIX,inoreader.com,选择代理
  - DOMAIN-SUFFIX,ip138.com,选择代理
  - DOMAIN-SUFFIX,linkedin.com,选择代理
  - DOMAIN-SUFFIX,myteamspeak.com,选择代理
  - DOMAIN-SUFFIX,notion.so,选择代理
  - DOMAIN-SUFFIX,ping.pe,选择代理
  - DOMAIN-SUFFIX,reddit.com,选择代理
  - DOMAIN-SUFFIX,teddysun.com,选择代理
  - DOMAIN-SUFFIX,tumbex.com,选择代理
  - DOMAIN-SUFFIX,twdvd.com,选择代理
  - DOMAIN-SUFFIX,unsplash.com,选择代理
  - DOMAIN-SUFFIX,buzzsprout.com,选择代理
  - DOMAIN-SUFFIX,eu,选择代理
  - DOMAIN-SUFFIX,hk,选择代理
  - DOMAIN-SUFFIX,jp,选择代理
  - DOMAIN-SUFFIX,kr,选择代理
  - DOMAIN-SUFFIX,sg,选择代理
  - DOMAIN-SUFFIX,tw,选择代理
  - DOMAIN-SUFFIX,uk,选择代理
  - DOMAIN-KEYWORD,1e100,选择代理
  - DOMAIN-KEYWORD,abema,选择代理
  - DOMAIN-KEYWORD,appledaily,选择代理
  - DOMAIN-KEYWORD,avtb,选择代理
  - DOMAIN-KEYWORD,beetalk,选择代理
  - DOMAIN-KEYWORD,blogspot,选择代理
  - DOMAIN-KEYWORD,dropbox,选择代理
  - DOMAIN-KEYWORD,facebook,选择代理
  - DOMAIN-KEYWORD,fbcdn,选择代理
  - DOMAIN-KEYWORD,github,选择代理
  - DOMAIN-KEYWORD,gmail,选择代理
  - DOMAIN-KEYWORD,google,选择代理
  - DOMAIN-KEYWORD,instagram,选择代理
  - DOMAIN-KEYWORD,porn,选择代理
  - DOMAIN-KEYWORD,sci-hub,选择代理
  - DOMAIN-KEYWORD,spotify,选择代理
  - DOMAIN-KEYWORD,telegram,选择代理
  - DOMAIN-KEYWORD,twitter,选择代理
  - DOMAIN-KEYWORD,whatsapp,选择代理
  - DOMAIN-KEYWORD,youtube,选择代理
  - DOMAIN-SUFFIX,4sqi.net,选择代理
  - DOMAIN-SUFFIX,a248.e.akamai.net,选择代理
  - DOMAIN-SUFFIX,adobedtm.com,选择代理
  - DOMAIN-SUFFIX,ampproject.org,选择代理
  - DOMAIN-SUFFIX,android.com,选择代理
  - DOMAIN-SUFFIX,aolcdn.com,选择代理
  - DOMAIN-SUFFIX,apkmirror.com,选择代理
  - DOMAIN-SUFFIX,apkpure.com,选择代理
  - DOMAIN-SUFFIX,app-measurement.com,选择代理
  - DOMAIN-SUFFIX,appspot.com,选择代理
  - DOMAIN-SUFFIX,archive.org,选择代理
  - DOMAIN-SUFFIX,armorgames.com,选择代理
  - DOMAIN-SUFFIX,aspnetcdn.com,选择代理
  - DOMAIN-SUFFIX,awsstatic.com,选择代理
  - DOMAIN-SUFFIX,azureedge.net,选择代理
  - DOMAIN-SUFFIX,azurewebsites.net,选择代理
  - DOMAIN-SUFFIX,bandwagonhost.com,选择代理
  - DOMAIN-SUFFIX,bing.com,选择代理
  - DOMAIN-SUFFIX,bkrtx.com,选择代理
  - DOMAIN-SUFFIX,blogcdn.com,选择代理
  - DOMAIN-SUFFIX,blogger.com,选择代理
  - DOMAIN-SUFFIX,blogsmithmedia.com,选择代理
  - DOMAIN-SUFFIX,blogspot.com,选择代理
  - DOMAIN-SUFFIX,blogspot.hk,选择代理
  - DOMAIN-SUFFIX,blogspot.jp,选择代理
  - DOMAIN-SUFFIX,bloomberg.cn,选择代理
  - DOMAIN-SUFFIX,bloomberg.com,选择代理
  - DOMAIN-SUFFIX,box.com,选择代理
  - DOMAIN-SUFFIX,cachefly.net,选择代理
  - DOMAIN-SUFFIX,cdnst.net,选择代理
  - DOMAIN-SUFFIX,cloudfront.net,选择代理
  - DOMAIN-SUFFIX,comodoca.com,选择代理
  - DOMAIN-SUFFIX,daum.net,选择代理
  - DOMAIN-SUFFIX,deskconnect.com,选择代理
  - DOMAIN-SUFFIX,disqus.com,选择代理
  - DOMAIN-SUFFIX,disquscdn.com,选择代理
  - DOMAIN-SUFFIX,dropbox.com,选择代理
  - DOMAIN-SUFFIX,dropboxapi.com,选择代理
  - DOMAIN-SUFFIX,dropboxstatic.com,选择代理
  - DOMAIN-SUFFIX,dropboxusercontent.com,选择代理
  - DOMAIN-SUFFIX,duckduckgo.com,选择代理
  - DOMAIN-SUFFIX,edgecastcdn.net,选择代理
  - DOMAIN-SUFFIX,edgekey.net,选择代理
  - DOMAIN-SUFFIX,edgesuite.net,选择代理
  - DOMAIN-SUFFIX,eurekavpt.com,选择代理
  - DOMAIN-SUFFIX,fastmail.com,选择代理
  - DOMAIN-SUFFIX,firebaseio.com,选择代理
  - DOMAIN-SUFFIX,flickr.com,选择代理
  - DOMAIN-SUFFIX,flipboard.com,选择代理
  - DOMAIN-SUFFIX,gfx.ms,选择代理
  - DOMAIN-SUFFIX,gongm.in,选择代理
  - DOMAIN-SUFFIX,hulu.com,选择代理
  - DOMAIN-SUFFIX,id.heroku.com,选择代理
  - DOMAIN-SUFFIX,io.io,选择代理
  - DOMAIN-SUFFIX,issuu.com,选择代理
  - DOMAIN-SUFFIX,ixquick.com,选择代理
  - DOMAIN-SUFFIX,jtvnw.net,选择代理
  - DOMAIN-SUFFIX,kat.cr,选择代理
  - DOMAIN-SUFFIX,kik.com,选择代理
  - DOMAIN-SUFFIX,kobo.com,选择代理
  - DOMAIN-SUFFIX,kobobooks.com,选择代理
  - DOMAIN-SUFFIX,licdn.com,选择代理
  - DOMAIN-SUFFIX,live.net,选择代理
  - DOMAIN-SUFFIX,livefilestore.com,选择代理
  - DOMAIN-SUFFIX,llnwd.net,选择代理
  - DOMAIN-SUFFIX,macrumors.com,选择代理
  - DOMAIN-SUFFIX,medium.com,选择代理
  - DOMAIN-SUFFIX,mega.nz,选择代理
  - DOMAIN-SUFFIX,megaupload.com,选择代理
  - DOMAIN-SUFFIX,messenger.com,选择代理
  - DOMAIN-SUFFIX,netdna-cdn.com,选择代理
  - DOMAIN-SUFFIX,nintendo.net,选择代理
  - DOMAIN-SUFFIX,nsstatic.net,选择代理
  - DOMAIN-SUFFIX,nytstyle.com,选择代理
  - DOMAIN-SUFFIX,overcast.fm,选择代理
  - DOMAIN-SUFFIX,openvpn.net,选择代理
  - DOMAIN-SUFFIX,periscope.tv,选择代理
  - DOMAIN-SUFFIX,pinimg.com,选择代理
  - DOMAIN-SUFFIX,pinterest.com,选择代理
  - DOMAIN-SUFFIX,potato.im,选择代理
  - DOMAIN-SUFFIX,prfct.co,选择代理
  - DOMAIN-SUFFIX,pscp.tv,选择代理
  - DOMAIN-SUFFIX,quora.com,选择代理
  - DOMAIN-SUFFIX,resilio.com,选择代理
  - DOMAIN-SUFFIX,sfx.ms,选择代理
  - DOMAIN-SUFFIX,shadowsocks.org,选择代理
  - DOMAIN-SUFFIX,slack-edge.com,选择代理
  - DOMAIN-SUFFIX,smartdnsproxy.com,选择代理
  - DOMAIN-SUFFIX,sndcdn.com,选择代理
  - DOMAIN-SUFFIX,soundcloud.com,选择代理
  - DOMAIN-SUFFIX,startpage.com,选择代理
  - DOMAIN-SUFFIX,staticflickr.com,选择代理
  - DOMAIN-SUFFIX,symauth.com,选择代理
  - DOMAIN-SUFFIX,symcb.com,选择代理
  - DOMAIN-SUFFIX,symcd.com,选择代理
  - DOMAIN-SUFFIX,textnow.com,选择代理
  - DOMAIN-SUFFIX,textnow.me,选择代理
  - DOMAIN-SUFFIX,thefacebook.com,选择代理
  - DOMAIN-SUFFIX,thepiratebay.org,选择代理
  - DOMAIN-SUFFIX,torproject.org,选择代理
  - DOMAIN-SUFFIX,trustasiassl.com,选择代理
  - DOMAIN-SUFFIX,tumblr.co,选择代理
  - DOMAIN-SUFFIX,tumblr.com,选择代理
  - DOMAIN-SUFFIX,tvb.com,选择代理
  - DOMAIN-SUFFIX,txmblr.com,选择代理
  - DOMAIN-SUFFIX,v2ex.com,选择代理
  - DOMAIN-SUFFIX,vimeo.com,选择代理
  - DOMAIN-SUFFIX,vine.co,选择代理
  - DOMAIN-SUFFIX,vox-cdn.com,选择代理
  - DOMAIN-SUFFIX,amazon.co.jp,选择代理
  - DOMAIN-SUFFIX,amazon.com,选择代理
  - DOMAIN-SUFFIX,amazonaws.com,选择代理
  - IP-CIDR,13.32.0.0/15,选择代理,no-resolve
  - IP-CIDR,13.35.0.0/17,选择代理,no-resolve
  - IP-CIDR,18.184.0.0/15,选择代理,no-resolve
  - IP-CIDR,18.194.0.0/15,选择代理,no-resolve
  - IP-CIDR,18.208.0.0/13,选择代理,no-resolve
  - IP-CIDR,18.232.0.0/14,选择代理,no-resolve
  - IP-CIDR,52.58.0.0/15,选择代理,no-resolve
  - IP-CIDR,52.74.0.0/16,选择代理,no-resolve
  - IP-CIDR,52.77.0.0/16,选择代理,no-resolve
  - IP-CIDR,52.84.0.0/15,选择代理,no-resolve
  - IP-CIDR,52.200.0.0/13,选择代理,no-resolve
  - IP-CIDR,54.93.0.0/16,选择代理,no-resolve
  - IP-CIDR,54.156.0.0/14,选择代理,no-resolve
  - IP-CIDR,54.226.0.0/15,选择代理,no-resolve
  - IP-CIDR,54.230.156.0/22,选择代理,no-resolve
  - DOMAIN-KEYWORD,uk-live,选择代理
  - DOMAIN-SUFFIX,bbc.co,选择代理
  - DOMAIN-SUFFIX,bbc.com,选择代理
  - DOMAIN-SUFFIX,claude.ai,选择代理
  - DOMAIN-SUFFIX,anthropic.com,选择代理
  - DOMAIN-SUFFIX,apache.org,选择代理
  - DOMAIN-SUFFIX,docker.com,选择代理
  - DOMAIN-SUFFIX,docker.io,选择代理
  - DOMAIN-SUFFIX,elastic.co,选择代理
  - DOMAIN-SUFFIX,elastic.com,选择代理
  - DOMAIN-SUFFIX,gcr.io,选择代理
  - DOMAIN-SUFFIX,gitlab.com,选择代理
  - DOMAIN-SUFFIX,gitlab.io,选择代理
  - DOMAIN-SUFFIX,jitpack.io,选择代理
  - DOMAIN-SUFFIX,maven.org,选择代理
  - DOMAIN-SUFFIX,medium.com,选择代理
  - DOMAIN-SUFFIX,mvnrepository.com,选择代理
  - DOMAIN-SUFFIX,quay.io,选择代理
  - DOMAIN-SUFFIX,reddit.com,选择代理
  - DOMAIN-SUFFIX,redhat.com,选择代理
  - DOMAIN-SUFFIX,sonatype.org,选择代理
  - DOMAIN-SUFFIX,sourcegraph.com,选择代理
  - DOMAIN-SUFFIX,spring.io,选择代理
  - DOMAIN-SUFFIX,spring.net,选择代理
  - DOMAIN-SUFFIX,stackoverflow.com,选择代理
  - DOMAIN,d1q6f0aelx0por.cloudfront.net,选择代理
  - DOMAIN,d2wy8f7a9ursnm.cloudfront.net,选择代理
  - DOMAIN,d36jcksde1wxzq.cloudfront.net,选择代理
  - DOMAIN-SUFFIX,compose-spec.io,选择代理
  - DOMAIN-SUFFIX,docker.com,选择代理
  - DOMAIN-SUFFIX,docker.io,选择代理
  - DOMAIN-SUFFIX,dockerhub.com,选择代理
  - DOMAIN-SUFFIX,discord.co,选择代理
  - DOMAIN-SUFFIX,discord.com,选择代理
  - DOMAIN-SUFFIX,discord.gg,选择代理
  - DOMAIN-SUFFIX,discord.media,选择代理
  - DOMAIN-SUFFIX,discordapp.com,选择代理
  - DOMAIN-SUFFIX,discordapp.net,选择代理
  - DOMAIN-SUFFIX,facebook.com,选择代理
  - DOMAIN-SUFFIX,fb.com,选择代理
  - DOMAIN-SUFFIX,fb.me,选择代理
  - DOMAIN-SUFFIX,fbcdn.com,选择代理
  - DOMAIN-SUFFIX,fbcdn.net,选择代理
  - IP-CIDR,31.13.24.0/21,选择代理,no-resolve
  - IP-CIDR,31.13.64.0/18,选择代理,no-resolve
  - IP-CIDR,45.64.40.0/22,选择代理,no-resolve
  - IP-CIDR,66.220.144.0/20,选择代理,no-resolve
  - IP-CIDR,69.63.176.0/20,选择代理,no-resolve
  - IP-CIDR,69.171.224.0/19,选择代理,no-resolve
  - IP-CIDR,74.119.76.0/22,选择代理,no-resolve
  - IP-CIDR,103.4.96.0/22,选择代理,no-resolve
  - IP-CIDR,129.134.0.0/17,选择代理,no-resolve
  - IP-CIDR,157.240.0.0/17,选择代理,no-resolve
  - IP-CIDR,173.252.64.0/18,选择代理,no-resolve
  - IP-CIDR,179.60.192.0/22,选择代理,no-resolve
  - IP-CIDR,185.60.216.0/22,选择代理,no-resolve
  - IP-CIDR,204.15.20.0/22,选择代理,no-resolve
  - DOMAIN-SUFFIX,github.com,选择代理
  - DOMAIN-SUFFIX,github.io,选择代理
  - DOMAIN-SUFFIX,githubapp.com,选择代理
  - DOMAIN-SUFFIX,githubassets.com,选择代理
  - DOMAIN-SUFFIX,githubusercontent.com,选择代理
  - DOMAIN-SUFFIX,1e100.net,选择代理
  - DOMAIN-SUFFIX,2mdn.net,选择代理
  - DOMAIN-SUFFIX,app-measurement.net,选择代理
  - DOMAIN-SUFFIX,g.co,选择代理
  - DOMAIN-SUFFIX,ggpht.com,选择代理
  - DOMAIN-SUFFIX,goo.gl,选择代理
  - DOMAIN-SUFFIX,googleapis.cn,选择代理
  - DOMAIN-SUFFIX,googleapis.com,选择代理
  - DOMAIN-SUFFIX,gstatic.cn,选择代理
  - DOMAIN-SUFFIX,gstatic.com,选择代理
  - DOMAIN-SUFFIX,gvt0.com,选择代理
  - DOMAIN-SUFFIX,gvt1.com,选择代理
  - DOMAIN-SUFFIX,gvt2.com,选择代理
  - DOMAIN-SUFFIX,gvt3.com,选择代理
  - DOMAIN-SUFFIX,xn--ngstr-lra8j.com,选择代理
  - DOMAIN-SUFFIX,youtu.be,选择代理
  - DOMAIN-SUFFIX,youtube-nocookie.com,选择代理
  - DOMAIN-SUFFIX,youtube.com,选择代理
  - DOMAIN-SUFFIX,yt.be,选择代理
  - DOMAIN-SUFFIX,ytimg.com,选择代理
  - IP-CIDR,74.125.0.0/16,选择代理,no-resolve
  - IP-CIDR,173.194.0.0/16,选择代理,no-resolve
  - IP-CIDR,120.232.181.162/32,选择代理,no-resolve
  - IP-CIDR,120.241.147.226/32,选择代理,no-resolve
  - IP-CIDR,120.253.253.226/32,选择代理,no-resolve
  - IP-CIDR,120.253.255.162/32,选择代理,no-resolve
  - IP-CIDR,120.253.255.34/32,选择代理,no-resolve
  - IP-CIDR,120.253.255.98/32,选择代理,no-resolve
  - IP-CIDR,180.163.150.162/32,选择代理,no-resolve
  - IP-CIDR,180.163.150.34/32,选择代理,no-resolve
  - IP-CIDR,180.163.151.162/32,选择代理,no-resolve
  - IP-CIDR,180.163.151.34/32,选择代理,no-resolve
  - IP-CIDR,203.208.39.0/24,选择代理,no-resolve
  - IP-CIDR,203.208.40.0/24,选择代理,no-resolve
  - IP-CIDR,203.208.41.0/24,选择代理,no-resolve
  - IP-CIDR,203.208.43.0/24,选择代理,no-resolve
  - IP-CIDR,203.208.50.0/24,选择代理,no-resolve
  - IP-CIDR,220.181.174.162/32,选择代理,no-resolve
  - IP-CIDR,220.181.174.226/32,选择代理,no-resolve
  - IP-CIDR,220.181.174.34/32,选择代理,no-resolve
  - DOMAIN-SUFFIX,cdninstagram.com,选择代理
  - DOMAIN-SUFFIX,instagram.com,选择代理
  - DOMAIN-SUFFIX,instagr.am,选择代理
  - DOMAIN-SUFFIX,iwara.tv,选择代理
  - DOMAIN-SUFFIX,kakao.com,选择代理
  - DOMAIN-SUFFIX,kakao.co.kr,选择代理
  - DOMAIN-SUFFIX,kakaocdn.net,选择代理
  - IP-CIDR,1.201.0.0/24,选择代理,no-resolve
  - IP-CIDR,27.0.236.0/22,选择代理,no-resolve
  - IP-CIDR,103.27.148.0/22,选择代理,no-resolve
  - IP-CIDR,103.246.56.0/22,选择代理,no-resolve
  - IP-CIDR,110.76.140.0/22,选择代理,no-resolve
  - IP-CIDR,113.61.104.0/22,选择代理,no-resolve
  - DOMAIN-SUFFIX,lin.ee,选择代理
  - DOMAIN-SUFFIX,line-apps.com,选择代理
  - DOMAIN-SUFFIX,line-cdn.net,选择代理
  - DOMAIN-SUFFIX,line-scdn.net,选择代理
  - DOMAIN-SUFFIX,line.me,选择代理
  - DOMAIN-SUFFIX,line.naver.jp,选择代理
  - DOMAIN-SUFFIX,nhncorp.jp,选择代理
  - IP-CIDR,103.2.28.0/24,选择代理,no-resolve
  - IP-CIDR,103.2.30.0/23,选择代理,no-resolve
  - IP-CIDR,119.235.224.0/24,选择代理,no-resolve
  - IP-CIDR,119.235.232.0/24,选择代理,no-resolve
  - IP-CIDR,119.235.235.0/24,选择代理,no-resolve
  - IP-CIDR,119.235.236.0/23,选择代理,no-resolve
  - IP-CIDR,147.92.128.0/17,选择代理,no-resolve
  - IP-CIDR,203.104.128.0/19,选择代理,no-resolve
  - DOMAIN-SUFFIX,openai.com,选择代理
  - DOMAIN-SUFFIX,challenges.cloudflare.com,选择代理
  - DOMAIN-KEYWORD,1drv,选择代理
  - DOMAIN-KEYWORD,onedrive,选择代理
  - DOMAIN-KEYWORD,skydrive,选择代理
  - DOMAIN-SUFFIX,livefilestore.com,选择代理
  - DOMAIN-SUFFIX,oneclient.sfx.ms,选择代理
  - DOMAIN-SUFFIX,onedrive.com,选择代理
  - DOMAIN-SUFFIX,onedrive.live.com,选择代理
  - DOMAIN-SUFFIX,photos.live.com,选择代理
  - DOMAIN-SUFFIX,skydrive.wns.windows.com,选择代理
  - DOMAIN-SUFFIX,spoprod-a.akamaihd.net,选择代理
  - DOMAIN-SUFFIX,storage.live.com,选择代理
  - DOMAIN-SUFFIX,storage.msn.com,选择代理
  - DOMAIN-KEYWORD,porn,选择代理
  - DOMAIN-SUFFIX,8teenxxx.com,选择代理
  - DOMAIN-SUFFIX,ahcdn.com,选择代理
  - DOMAIN-SUFFIX,bcvcdn.com,选择代理
  - DOMAIN-SUFFIX,bongacams.com,选择代理
  - DOMAIN-SUFFIX,chaturbate.com,选择代理
  - DOMAIN-SUFFIX,dditscdn.com,选择代理
  - DOMAIN-SUFFIX,livejasmin.com,选择代理
  - DOMAIN-SUFFIX,phncdn.com,选择代理
  - DOMAIN-SUFFIX,phprcdn.com,选择代理
  - DOMAIN-SUFFIX,pornhub.com,选择代理
  - DOMAIN-SUFFIX,pornhubpremium.com,选择代理
  - DOMAIN-SUFFIX,rdtcdn.com,选择代理
  - DOMAIN-SUFFIX,redtube.com,选择代理
  - DOMAIN-SUFFIX,sb-cd.com,选择代理
  - DOMAIN-SUFFIX,spankbang.com,选择代理
  - DOMAIN-SUFFIX,t66y.com,选择代理
  - DOMAIN-SUFFIX,xhamster.com,选择代理
  - DOMAIN-SUFFIX,xnxx-cdn.com,选择代理
  - DOMAIN-SUFFIX,xnxx.com,选择代理
  - DOMAIN-SUFFIX,xvideos-cdn.com,选择代理
  - DOMAIN-SUFFIX,xvideos.com,选择代理
  - DOMAIN-SUFFIX,ypncdn.com,选择代理
  - DOMAIN-SUFFIX,pixiv.net,选择代理
  - DOMAIN-SUFFIX,pximg.net,选择代理
  - DOMAIN-SUFFIX,fanbox.cc,选择代理
  - DOMAIN-SUFFIX,amplitude.com,选择代理
  - DOMAIN-SUFFIX,firebaseio.com,选择代理
  - DOMAIN-SUFFIX,hockeyapp.net,选择代理
  - DOMAIN-SUFFIX,readdle.com,选择代理
  - DOMAIN-SUFFIX,smartmailcloud.com,选择代理
  - DOMAIN-SUFFIX,fanatical.com,选择代理
  - DOMAIN-SUFFIX,humblebundle.com,选择代理
  - DOMAIN-SUFFIX,underlords.com,选择代理
  - DOMAIN-SUFFIX,valvesoftware.com,选择代理
  - DOMAIN-SUFFIX,playartifact.com,选择代理
  - DOMAIN-SUFFIX,steam-chat.com,选择代理
  - DOMAIN-SUFFIX,steamcommunity.com,选择代理
  - DOMAIN-SUFFIX,steamgames.com,选择代理
  - DOMAIN-SUFFIX,steampowered.com,选择代理
  - DOMAIN-SUFFIX,steamserver.net,选择代理
  - DOMAIN-SUFFIX,steamstatic.com,选择代理
  - DOMAIN-SUFFIX,steamstat.us,选择代理
  - DOMAIN,steambroadcast.akamaized.net,选择代理
  - DOMAIN,steamcommunity-a.akamaihd.net,选择代理
  - DOMAIN,steamstore-a.akamaihd.net,选择代理
  - DOMAIN,steamusercontent-a.akamaihd.net,选择代理
  - DOMAIN,steamuserimages-a.akamaihd.net,选择代理
  - DOMAIN,steampipe.akamaized.net,选择代理
  - DOMAIN-SUFFIX,tap.io,选择代理
  - DOMAIN-SUFFIX,taptap.tw,选择代理
  - DOMAIN-SUFFIX,twitch.tv,选择代理
  - DOMAIN-SUFFIX,ttvnw.net,选择代理
  - DOMAIN-SUFFIX,jtvnw.net,选择代理
  - DOMAIN-KEYWORD,ttvnw,选择代理
  - DOMAIN-SUFFIX,t.co,选择代理
  - DOMAIN-SUFFIX,twimg.co,选择代理
  - DOMAIN-SUFFIX,twimg.com,选择代理
  - DOMAIN-SUFFIX,twimg.org,选择代理
  - DOMAIN-SUFFIX,x.com,选择代理
  - DOMAIN-SUFFIX,t.me,选择代理
  - DOMAIN-SUFFIX,tdesktop.com,选择代理
  - DOMAIN-SUFFIX,telegra.ph,选择代理
  - DOMAIN-SUFFIX,telegram.me,选择代理
  - DOMAIN-SUFFIX,telegram.org,选择代理
  - DOMAIN-SUFFIX,telesco.pe,选择代理
  - IP-CIDR,91.108.0.0/16,选择代理,no-resolve
  - IP-CIDR,109.239.140.0/24,选择代理,no-resolve
  - IP-CIDR,149.154.160.0/20,选择代理,no-resolve
  - IP-CIDR6,2001:67c:4e8::/48,选择代理,no-resolve
  - IP-CIDR6,2001:b28:f23d::/48,选择代理,no-resolve
  - IP-CIDR6,2001:b28:f23f::/48,选择代理,no-resolve
  - DOMAIN-SUFFIX,terabox.com,选择代理
  - DOMAIN-SUFFIX,teraboxcdn.com,选择代理
  - IP-CIDR,18.194.0.0/15,选择代理,no-resolve
  - IP-CIDR,34.224.0.0/12,选择代理,no-resolve
  - IP-CIDR,54.242.0.0/15,选择代理,no-resolve
  - IP-CIDR,50.22.198.204/30,选择代理,no-resolve
  - IP-CIDR,208.43.122.128/27,选择代理,no-resolve
  - IP-CIDR,108.168.174.0/16,选择代理,no-resolve
  - IP-CIDR,173.192.231.32/27,选择代理,no-resolve
  - IP-CIDR,158.85.5.192/27,选择代理,no-resolve
  - IP-CIDR,174.37.243.0/16,选择代理,no-resolve
  - IP-CIDR,158.85.46.128/27,选择代理,no-resolve
  - IP-CIDR,173.192.222.160/27,选择代理,no-resolve
  - IP-CIDR,184.173.128.0/17,选择代理,no-resolve
  - IP-CIDR,158.85.224.160/27,选择代理,no-resolve
  - IP-CIDR,75.126.150.0/16,选择代理,no-resolve
  - IP-CIDR,69.171.235.0/16,选择代理,no-resolve
  - DOMAIN-SUFFIX,mediawiki.org,选择代理
  - DOMAIN-SUFFIX,wikibooks.org,选择代理
  - DOMAIN-SUFFIX,wikidata.org,选择代理
  - DOMAIN-SUFFIX,wikileaks.org,选择代理
  - DOMAIN-SUFFIX,wikimedia.org,选择代理
  - DOMAIN-SUFFIX,wikinews.org,选择代理
  - DOMAIN-SUFFIX,wikipedia.org,选择代理
  - DOMAIN-SUFFIX,wikiquote.org,选择代理
  - DOMAIN-SUFFIX,wikisource.org,选择代理
  - DOMAIN-SUFFIX,wikiversity.org,选择代理
  - DOMAIN-SUFFIX,wikivoyage.org,选择代理
  - DOMAIN-SUFFIX,wiktionary.org,选择代理
  - DOMAIN-SUFFIX,zoom.us,选择代理
  - DOMAIN-SUFFIX,zoomgov.com,选择代理
  - DOMAIN-SUFFIX,neulion.com,选择代理
  - DOMAIN-SUFFIX,icntv.xyz,选择代理
  - DOMAIN-SUFFIX,flzbcdn.xyz,选择代理
  - DOMAIN-SUFFIX,ocnttv.com,选择代理
  - DOMAIN-SUFFIX,vikacg.com,选择代理
  - DOMAIN-SUFFIX,picjs.xyz,选择代理
  - DOMAIN-SUFFIX,13th.tech,选择代理
  - DOMAIN-SUFFIX,423down.com,选择代理
  - DOMAIN-SUFFIX,bokecc.com,选择代理
  - DOMAIN-SUFFIX,chaipip.com,选择代理
  - DOMAIN-SUFFIX,chinaplay.store,选择代理
  - DOMAIN-SUFFIX,hrtsea.com,选择代理
  - DOMAIN-SUFFIX,kaikeba.com,选择代理
  - DOMAIN-SUFFIX,laomo.me,选择代理
  - DOMAIN-SUFFIX,mpyit.com,选择代理
  - DOMAIN-SUFFIX,msftconnecttest.com,选择代理
  - DOMAIN-SUFFIX,msftncsi.com,选择代理
  - DOMAIN-SUFFIX,qupu123.com,选择代理
  - DOMAIN-SUFFIX,pdfwifi.com,选择代理
  - DOMAIN-SUFFIX,zhenguanyu.biz,选择代理
  - DOMAIN-SUFFIX,zhenguanyu.com,选择代理
  - DOMAIN-SUFFIX,snapdrop.net,选择代理
  - DOMAIN-SUFFIX,tebex.io,选择代理
  - DOMAIN-SUFFIX,cn,选择代理
  - DOMAIN-SUFFIX,xn--fiqs8s,选择代理
  - DOMAIN-SUFFIX,xn--55qx5d,选择代理
  - DOMAIN-SUFFIX,xn--io0a7i,选择代理
  - DOMAIN-KEYWORD,360buy,选择代理
  - DOMAIN-KEYWORD,alicdn,选择代理
  - DOMAIN-KEYWORD,alimama,选择代理
  - DOMAIN-KEYWORD,alipay,选择代理
  - DOMAIN-KEYWORD,appzapp,选择代理
  - DOMAIN-KEYWORD,baidupcs,选择代理
  - DOMAIN-KEYWORD,bilibili,选择代理
  - DOMAIN-KEYWORD,ccgslb,选择代理
  - DOMAIN-KEYWORD,chinacache,选择代理
  - DOMAIN-KEYWORD,duobao,选择代理
  - DOMAIN-KEYWORD,jdpay,选择代理
  - DOMAIN-KEYWORD,moke,选择代理
  - DOMAIN-KEYWORD,qhimg,选择代理
  - DOMAIN-KEYWORD,vpimg,选择代理
  - DOMAIN-KEYWORD,xiami,选择代理
  - DOMAIN-KEYWORD,xiaomi,选择代理
  - DOMAIN-SUFFIX,360.com,选择代理
  - DOMAIN-SUFFIX,360kuai.com,选择代理
  - DOMAIN-SUFFIX,360safe.com,选择代理
  - DOMAIN-SUFFIX,dhrest.com,选择代理
  - DOMAIN-SUFFIX,qhres.com,选择代理
  - DOMAIN-SUFFIX,qhstatic.com,选择代理
  - DOMAIN-SUFFIX,qhupdate.com,选择代理
  - DOMAIN-SUFFIX,so.com,选择代理
  - DOMAIN-SUFFIX,4399.com,选择代理
  - DOMAIN-SUFFIX,4399pk.com,选择代理
  - DOMAIN-SUFFIX,5054399.com,选择代理
  - DOMAIN-SUFFIX,img4399.com,选择代理
  - DOMAIN-SUFFIX,58.com,选择代理
  - DOMAIN-SUFFIX,1688.com,选择代理
  - DOMAIN-SUFFIX,aliapp.org,选择代理
  - DOMAIN-SUFFIX,alibaba.com,选择代理
  - DOMAIN-SUFFIX,alibabacloud.com,选择代理
  - DOMAIN-SUFFIX,alibabausercontent.com,选择代理
  - DOMAIN-SUFFIX,alicdn.com,选择代理
  - DOMAIN-SUFFIX,alicloudccp.com,选择代理
  - DOMAIN-SUFFIX,aliexpress.com,选择代理
  - DOMAIN-SUFFIX,aliimg.com,选择代理
  - DOMAIN-SUFFIX,alikunlun.com,选择代理
  - DOMAIN-SUFFIX,alipay.com,选择代理
  - DOMAIN-SUFFIX,alipayobjects.com,选择代理
  - DOMAIN-SUFFIX,alisoft.com,选择代理
  - DOMAIN-SUFFIX,aliyun.com,选择代理
  - DOMAIN-SUFFIX,aliyuncdn.com,选择代理
  - DOMAIN-SUFFIX,aliyuncs.com,选择代理
  - DOMAIN-SUFFIX,aliyundrive.com,选择代理
  - DOMAIN-SUFFIX,aliyundrive.net,选择代理
  - DOMAIN-SUFFIX,amap.com,选择代理
  - DOMAIN-SUFFIX,autonavi.com,选择代理
  - DOMAIN-SUFFIX,dingtalk.com,选择代理
  - DOMAIN-SUFFIX,ele.me,选择代理
  - DOMAIN-SUFFIX,hichina.com,选择代理
  - DOMAIN-SUFFIX,mmstat.com,选择代理
  - DOMAIN-SUFFIX,mxhichina.com,选择代理
  - DOMAIN-SUFFIX,soku.com,选择代理
  - DOMAIN-SUFFIX,taobao.com,选择代理
  - DOMAIN-SUFFIX,taobaocdn.com,选择代理
  - DOMAIN-SUFFIX,tbcache.com,选择代理
  - DOMAIN-SUFFIX,tbcdn.com,选择代理
  - DOMAIN-SUFFIX,tmall.com,选择代理
  - DOMAIN-SUFFIX,tmall.hk,选择代理
  - DOMAIN-SUFFIX,ucweb.com,选择代理
  - DOMAIN-SUFFIX,xiami.com,选择代理
  - DOMAIN-SUFFIX,xiami.net,选择代理
  - DOMAIN-SUFFIX,ykimg.com,选择代理
  - DOMAIN-SUFFIX,youku.com,选择代理
  - DOMAIN-SUFFIX,baidu.com,选择代理
  - DOMAIN-SUFFIX,baidubcr.com,选择代理
  - DOMAIN-SUFFIX,baidupcs.com,选择代理
  - DOMAIN-SUFFIX,baidustatic.com,选择代理
  - DOMAIN-SUFFIX,bcebos.com,选择代理
  - DOMAIN-SUFFIX,bdimg.com,选择代理
  - DOMAIN-SUFFIX,bdstatic.com,选择代理
  - DOMAIN-SUFFIX,bdurl.net,选择代理
  - DOMAIN-SUFFIX,hao123.com,选择代理
  - DOMAIN-SUFFIX,hao123img.com,选择代理
  - DOMAIN-SUFFIX,jomodns.com,选择代理
  - DOMAIN-SUFFIX,yunjiasu-cdn.net,选择代理
  - DOMAIN-SUFFIX,acg.tv,选择代理
  - DOMAIN-SUFFIX,acgvideo.com,选择代理
  - DOMAIN-SUFFIX,b23.tv,选择代理
  - DOMAIN-SUFFIX,bigfun.cn,选择代理
  - DOMAIN-SUFFIX,bigfunapp.cn,选择代理
  - DOMAIN-SUFFIX,biliapi.com,选择代理
  - DOMAIN-SUFFIX,biliapi.net,选择代理
  - DOMAIN-SUFFIX,bilibili.com,选择代理
  - DOMAIN-SUFFIX,bilibili.co,选择代理
  - DOMAIN-SUFFIX,biliintl.co,选择代理
  - DOMAIN-SUFFIX,biligame.com,选择代理
  - DOMAIN-SUFFIX,biligame.net,选择代理
  - DOMAIN-SUFFIX,bilivideo.com,选择代理
  - DOMAIN-SUFFIX,bilivideo.cn,选择代理
  - DOMAIN-SUFFIX,hdslb.com,选择代理
  - DOMAIN-SUFFIX,im9.com,选择代理
  - DOMAIN-SUFFIX,smtcdns.net,选择代理
  - DOMAIN-SUFFIX,amemv.com,选择代理
  - DOMAIN-SUFFIX,bdxiguaimg.com,选择代理
  - DOMAIN-SUFFIX,bdxiguastatic.com,选择代理
  - DOMAIN-SUFFIX,byted-static.com,选择代理
  - DOMAIN-SUFFIX,bytedance.com,选择代理
  - DOMAIN-SUFFIX,bytedance.net,选择代理
  - DOMAIN-SUFFIX,bytedns.net,选择代理
  - DOMAIN-SUFFIX,bytednsdoc.com,选择代理
  - DOMAIN-SUFFIX,bytegoofy.com,选择代理
  - DOMAIN-SUFFIX,byteimg.com,选择代理
  - DOMAIN-SUFFIX,bytescm.com,选择代理
  - DOMAIN-SUFFIX,bytetos.com,选择代理
  - DOMAIN-SUFFIX,bytexservice.com,选择代理
  - DOMAIN-SUFFIX,douyin.com,选择代理
  - DOMAIN-SUFFIX,douyincdn.com,选择代理
  - DOMAIN-SUFFIX,douyinpic.com,选择代理
  - DOMAIN-SUFFIX,douyinstatic.com,选择代理
  - DOMAIN-SUFFIX,douyinvod.com,选择代理
  - DOMAIN-SUFFIX,feelgood.cn,选择代理
  - DOMAIN-SUFFIX,feiliao.com,选择代理
  - DOMAIN-SUFFIX,gifshow.com,选择代理
  - DOMAIN-SUFFIX,huoshan.com,选择代理
  - DOMAIN-SUFFIX,huoshanzhibo.com,选择代理
  - DOMAIN-SUFFIX,ibytedapm.com,选择代理
  - DOMAIN-SUFFIX,iesdouyin.com,选择代理
  - DOMAIN-SUFFIX,ixigua.com,选择代理
  - DOMAIN-SUFFIX,kspkg.com,选择代理
  - DOMAIN-SUFFIX,pstatp.com,选择代理
  - DOMAIN-SUFFIX,snssdk.com,选择代理
  - DOMAIN-SUFFIX,toutiao.com,选择代理
  - DOMAIN-SUFFIX,toutiao13.com,选择代理
  - DOMAIN-SUFFIX,toutiaoapi.com,选择代理
  - DOMAIN-SUFFIX,toutiaocdn.com,选择代理
  - DOMAIN-SUFFIX,toutiaocdn.net,选择代理
  - DOMAIN-SUFFIX,toutiaocloud.com,选择代理
  - DOMAIN-SUFFIX,toutiaohao.com,选择代理
  - DOMAIN-SUFFIX,toutiaohao.net,选择代理
  - DOMAIN-SUFFIX,toutiaoimg.com,选择代理
  - DOMAIN-SUFFIX,toutiaopage.com,选择代理
  - DOMAIN-SUFFIX,wukong.com,选择代理
  - DOMAIN-SUFFIX,zijieapi.com,选择代理
  - DOMAIN-SUFFIX,zijieimg.com,选择代理
  - DOMAIN-SUFFIX,zjbyte.com,选择代理
  - DOMAIN-SUFFIX,zjcdn.com,选择代理
  - DOMAIN-SUFFIX,cctv.com,选择代理
  - DOMAIN-SUFFIX,cctvpic.com,选择代理
  - DOMAIN-SUFFIX,livechina.com,选择代理
  - DOMAIN-SUFFIX,21cn.com,选择代理
  - DOMAIN-SUFFIX,didialift.com,选择代理
  - DOMAIN-SUFFIX,didiglobal.com,选择代理
  - DOMAIN-SUFFIX,udache.com,选择代理
  - DOMAIN-SUFFIX,bytefcdnrd.com,选择代理
  - DOMAIN-SUFFIX,edgesrv.com,选择代理
  - DOMAIN-SUFFIX,douyu.com,选择代理
  - DOMAIN-SUFFIX,douyu.tv,选择代理
  - DOMAIN-SUFFIX,douyuscdn.com,选择代理
  - DOMAIN-SUFFIX,douyutv.com,选择代理
  - DOMAIN-SUFFIX,epicgames.com,选择代理
  - DOMAIN-SUFFIX,epicgames.dev,选择代理
  - DOMAIN-SUFFIX,helpshift.com,选择代理
  - DOMAIN-SUFFIX,paragon.com,选择代理
  - DOMAIN-SUFFIX,unrealengine.com,选择代理
  - DOMAIN-SUFFIX,dbankcdn.com,选择代理
  - DOMAIN-SUFFIX,hc-cdn.com,选择代理
  - DOMAIN-SUFFIX,hicloud.com,选择代理
  - DOMAIN-SUFFIX,hihonor.com,选择代理
  - DOMAIN-SUFFIX,huawei.com,选择代理
  - DOMAIN-SUFFIX,huaweicloud.com,选择代理
  - DOMAIN-SUFFIX,huaweishop.net,选择代理
  - DOMAIN-SUFFIX,hwccpc.com,选择代理
  - DOMAIN-SUFFIX,vmall.com,选择代理
  - DOMAIN-SUFFIX,vmallres.com,选择代理
  - DOMAIN-SUFFIX,allawnfs.com,选择代理
  - DOMAIN-SUFFIX,allawno.com,选择代理
  - DOMAIN-SUFFIX,allawntech.com,选择代理
  - DOMAIN-SUFFIX,coloros.com,选择代理
  - DOMAIN-SUFFIX,heytap.com,选择代理
  - DOMAIN-SUFFIX,heytapcs.com,选择代理
  - DOMAIN-SUFFIX,heytapdownload.com,选择代理
  - DOMAIN-SUFFIX,heytapimage.com,选择代理
  - DOMAIN-SUFFIX,heytapmobi.com,选择代理
  - DOMAIN-SUFFIX,oppo.com,选择代理
  - DOMAIN-SUFFIX,oppoer.me,选择代理
  - DOMAIN-SUFFIX,oppomobile.com,选择代理
  - DOMAIN-SUFFIX,iflyink.com,选择代理
  - DOMAIN-SUFFIX,iflyrec.com,选择代理
  - DOMAIN-SUFFIX,iflytek.com,选择代理
  - DOMAIN-SUFFIX,71.am,选择代理
  - DOMAIN-SUFFIX,71edge.com,选择代理
  - DOMAIN-SUFFIX,iqiyi.com,选择代理
  - DOMAIN-SUFFIX,iqiyipic.com,选择代理
  - DOMAIN-SUFFIX,ppsimg.com,选择代理
  - DOMAIN-SUFFIX,qiyi.com,选择代理
  - DOMAIN-SUFFIX,qiyipic.com,选择代理
  - DOMAIN-SUFFIX,qy.net,选择代理
  - DOMAIN-SUFFIX,360buy.com,选择代理
  - DOMAIN-SUFFIX,360buyimg.com,选择代理
  - DOMAIN-SUFFIX,jcloudcs.com,选择代理
  - DOMAIN-SUFFIX,jd.com,选择代理
  - DOMAIN-SUFFIX,jd.hk,选择代理
  - DOMAIN-SUFFIX,jdcloud.com,选择代理
  - DOMAIN-SUFFIX,jdpay.com,选择代理
  - DOMAIN-SUFFIX,paipai.com,选择代理
  - DOMAIN-SUFFIX,iciba.com,选择代理
  - DOMAIN-SUFFIX,ksosoft.com,选择代理
  - DOMAIN-SUFFIX,ksyun.com,选择代理
  - DOMAIN-SUFFIX,kuaishou.com,选择代理
  - DOMAIN-SUFFIX,yximgs.com,选择代理
  - DOMAIN-SUFFIX,meitu.com,选择代理
  - DOMAIN-SUFFIX,meitudata.com,选择代理
  - DOMAIN-SUFFIX,meitustat.com,选择代理
  - DOMAIN-SUFFIX,meipai.com,选择代理
  - DOMAIN-SUFFIX,le.com,选择代理
  - DOMAIN-SUFFIX,lecloud.com,选择代理
  - DOMAIN-SUFFIX,letv.com,选择代理
  - DOMAIN-SUFFIX,letvcloud.com,选择代理
  - DOMAIN-SUFFIX,letvimg.com,选择代理
  - DOMAIN-SUFFIX,letvlive.com,选择代理
  - DOMAIN-SUFFIX,letvstore.com,选择代理
  - DOMAIN-SUFFIX,hitv.com,选择代理
  - DOMAIN-SUFFIX,hunantv.com,选择代理
  - DOMAIN-SUFFIX,mgtv.com,选择代理
  - DOMAIN-SUFFIX,duokan.com,选择代理
  - DOMAIN-SUFFIX,mi-img.com,选择代理
  - DOMAIN-SUFFIX,mi.com,选择代理
  - DOMAIN-SUFFIX,miui.com,选择代理
  - DOMAIN-SUFFIX,xiaomi.com,选择代理
  - DOMAIN-SUFFIX,xiaomi.net,选择代理
  - DOMAIN-SUFFIX,xiaomicp.com,选择代理
  - DOMAIN-SUFFIX,126.com,选择代理
  - DOMAIN-SUFFIX,126.net,选择代理
  - DOMAIN-SUFFIX,127.net,选择代理
  - DOMAIN-SUFFIX,163.com,选择代理
  - DOMAIN-SUFFIX,163yun.com,选择代理
  - DOMAIN-SUFFIX,lofter.com,选择代理
  - DOMAIN-SUFFIX,netease.com,选择代理
  - DOMAIN-SUFFIX,ydstatic.com,选择代理
  - DOMAIN-SUFFIX,youdao.com,选择代理
  - DOMAIN-SUFFIX,pplive.com,选择代理
  - DOMAIN-SUFFIX,pptv.com,选择代理
  - DOMAIN-SUFFIX,pinduoduo.com,选择代理
  - DOMAIN-SUFFIX,yangkeduo.com,选择代理
  - DOMAIN-SUFFIX,leju.com,选择代理
  - DOMAIN-SUFFIX,miaopai.com,选择代理
  - DOMAIN-SUFFIX,sina.com,选择代理
  - DOMAIN-SUFFIX,sina.com.cn,选择代理
  - DOMAIN-SUFFIX,sina.cn,选择代理
  - DOMAIN-SUFFIX,sinaapp.com,选择代理
  - DOMAIN-SUFFIX,sinaapp.cn,选择代理
  - DOMAIN-SUFFIX,sinaimg.com,选择代理
  - DOMAIN-SUFFIX,sinaimg.cn,选择代理
  - DOMAIN-SUFFIX,weibo.com,选择代理
  - DOMAIN-SUFFIX,weibo.cn,选择代理
  - DOMAIN-SUFFIX,weibocdn.com,选择代理
  - DOMAIN-SUFFIX,weibocdn.cn,选择代理
  - DOMAIN-SUFFIX,xiaoka.tv,选择代理
  - DOMAIN-SUFFIX,go2map.com,选择代理
  - DOMAIN-SUFFIX,sogo.com,选择代理
  - DOMAIN-SUFFIX,sogou.com,选择代理
  - DOMAIN-SUFFIX,sogoucdn.com,选择代理
  - DOMAIN-SUFFIX,sohu-inc.com,选择代理
  - DOMAIN-SUFFIX,sohu.com,选择代理
  - DOMAIN-SUFFIX,sohucs.com,选择代理
  - DOMAIN-SUFFIX,sohuno.com,选择代理
  - DOMAIN-SUFFIX,sohurdc.com,选择代理
  - DOMAIN-SUFFIX,v-56.com,选择代理
  - DOMAIN-SUFFIX,playstation.com,选择代理
  - DOMAIN-SUFFIX,playstation.net,选择代理
  - DOMAIN-SUFFIX,playstationnetwork.com,选择代理
  - DOMAIN-SUFFIX,sony.com,选择代理
  - DOMAIN-SUFFIX,sonyentertainmentnetwork.com,选择代理
  - DOMAIN-SUFFIX,cm.steampowered.com,选择代理
  - DOMAIN-SUFFIX,steamcontent.com,选择代理
  - DOMAIN-SUFFIX,steamusercontent.com,选择代理
  - DOMAIN-SUFFIX,steamchina.com,选择代理
  - DOMAIN,csgo.wmsj.cn,选择代理
  - DOMAIN,dota2.wmsj.cn,选择代理
  - DOMAIN,wmsjsteam.com,选择代理
  - DOMAIN,dl.steam.clngaa.com,选择代理
  - DOMAIN,dl.steam.ksyna.com,选择代理
  - DOMAIN,st.dl.bscstorage.net,选择代理
  - DOMAIN,st.dl.eccdnx.com,选择代理
  - DOMAIN,st.dl.pinyuncloud.com,选择代理
  - DOMAIN,xz.pphimalayanrt.com,选择代理
  - DOMAIN,steampipe.steamcontent.tnkjmec.com,选择代理
  - DOMAIN,steampowered.com.8686c.com,选择代理
  - DOMAIN,steamstatic.com.8686c.com,选择代理
  - DOMAIN-SUFFIX,foxmail.com,选择代理
  - DOMAIN-SUFFIX,gtimg.com,选择代理
  - DOMAIN-SUFFIX,idqqimg.com,选择代理
  - DOMAIN-SUFFIX,igamecj.com,选择代理
  - DOMAIN-SUFFIX,myapp.com,选择代理
  - DOMAIN-SUFFIX,myqcloud.com,选择代理
  - DOMAIN-SUFFIX,qq.com,选择代理
  - DOMAIN-SUFFIX,qqmail.com,选择代理
  - DOMAIN-SUFFIX,qqurl.com,选择代理
  - DOMAIN-SUFFIX,smtcdns.com,选择代理
  - DOMAIN-SUFFIX,smtcdns.net,选择代理
  - DOMAIN-SUFFIX,soso.com,选择代理
  - DOMAIN-SUFFIX,tencent-cloud.net,选择代理
  - DOMAIN-SUFFIX,tencent.com,选择代理
  - DOMAIN-SUFFIX,tencentmind.com,选择代理
  - DOMAIN-SUFFIX,tenpay.com,选择代理
  - DOMAIN-SUFFIX,wechat.com,选择代理
  - DOMAIN-SUFFIX,weixin.com,选择代理
  - DOMAIN-SUFFIX,weiyun.com,选择代理
  - DOMAIN-SUFFIX,appsimg.com,选择代理
  - DOMAIN-SUFFIX,appvipshop.com,选择代理
  - DOMAIN-SUFFIX,vip.com,选择代理
  - DOMAIN-SUFFIX,vipstatic.com,选择代理
  - DOMAIN-SUFFIX,ximalaya.com,选择代理
  - DOMAIN-SUFFIX,xmcdn.com,选择代理
  - DOMAIN-SUFFIX,00cdn.com,选择代理
  - DOMAIN-SUFFIX,88cdn.com,选择代理
  - DOMAIN-SUFFIX,kanimg.com,选择代理
  - DOMAIN-SUFFIX,kankan.com,选择代理
  - DOMAIN-SUFFIX,p2cdn.com,选择代理
  - DOMAIN-SUFFIX,sandai.net,选择代理
  - DOMAIN-SUFFIX,thundercdn.com,选择代理
  - DOMAIN-SUFFIX,xunlei.com,选择代理
  - DOMAIN-SUFFIX,got001.com,选择代理
  - DOMAIN-SUFFIX,p4pfile.com,选择代理
  - DOMAIN-SUFFIX,rrys.tv,选择代理
  - DOMAIN-SUFFIX,rrys2020.com,选择代理
  - DOMAIN-SUFFIX,yyets.com,选择代理
  - DOMAIN-SUFFIX,zimuzu.io,选择代理
  - DOMAIN-SUFFIX,zimuzu.tv,选择代理
  - DOMAIN-SUFFIX,zmz001.com,选择代理
  - DOMAIN-SUFFIX,zmz002.com,选择代理
  - DOMAIN-SUFFIX,zmz003.com,选择代理
  - DOMAIN-SUFFIX,zmz004.com,选择代理
  - DOMAIN-SUFFIX,zmz2019.com,选择代理
  - DOMAIN-SUFFIX,zmzapi.com,选择代理
  - DOMAIN-SUFFIX,zmzapi.net,选择代理
  - DOMAIN-SUFFIX,zmzfile.com,选择代理
  - DOMAIN-SUFFIX,teamviewer.com,选择代理
  - IP-CIDR,139.220.243.27/32,选择代理,no-resolve
  - IP-CIDR,172.16.102.56/32,选择代理,no-resolve
  - IP-CIDR,185.188.32.1/28,选择代理,no-resolve
  - IP-CIDR,221.226.128.146/32,选择代理,no-resolve
  - IP-CIDR6,2a0b:b580::/48,选择代理,no-resolve
  - IP-CIDR6,2a0b:b581::/48,选择代理,no-resolve
  - IP-CIDR6,2a0b:b582::/48,选择代理,no-resolve
  - IP-CIDR6,2a0b:b583::/48,选择代理,no-resolve
  - DOMAIN-SUFFIX,baomitu.com,选择代理
  - DOMAIN-SUFFIX,bootcss.com,选择代理
  - DOMAIN-SUFFIX,jiasule.com,选择代理
  - DOMAIN-SUFFIX,staticfile.org,选择代理
  - DOMAIN-SUFFIX,upaiyun.com,选择代理
  - DOMAIN-SUFFIX,doh.pub,选择代理
  - DOMAIN-SUFFIX,dns.alidns.com,选择代理
  - DOMAIN-SUFFIX,doh.360.cn,选择代理
  - IP-CIDR,1.12.12.12/32,选择代理,no-resolve
  - DOMAIN-SUFFIX,10010.com,选择代理
  - DOMAIN-SUFFIX,115.com,选择代理
  - DOMAIN-SUFFIX,12306.com,选择代理
  - DOMAIN-SUFFIX,17173.com,选择代理
  - DOMAIN-SUFFIX,178.com,选择代理
  - DOMAIN-SUFFIX,17k.com,选择代理
  - DOMAIN-SUFFIX,360doc.com,选择代理
  - DOMAIN-SUFFIX,36kr.com,选择代理
  - DOMAIN-SUFFIX,3dmgame.com,选择代理
  - DOMAIN-SUFFIX,51cto.com,选择代理
  - DOMAIN-SUFFIX,51job.com,选择代理
  - DOMAIN-SUFFIX,51jobcdn.com,选择代理
  - DOMAIN-SUFFIX,56.com,选择代理
  - DOMAIN-SUFFIX,8686c.com,选择代理
  - DOMAIN-SUFFIX,abchina.com,选择代理
  - DOMAIN-SUFFIX,abercrombie.com,选择代理
  - DOMAIN-SUFFIX,acfun.tv,选择代理
  - DOMAIN-SUFFIX,air-matters.com,选择代理
  - DOMAIN-SUFFIX,air-matters.io,选择代理
  - DOMAIN-SUFFIX,aixifan.com,选择代理
  - DOMAIN-SUFFIX,algocasts.io,选择代理
  - DOMAIN-SUFFIX,babytree.com,选择代理
  - DOMAIN-SUFFIX,babytreeimg.com,选择代理
  - DOMAIN-SUFFIX,baicizhan.com,选择代理
  - DOMAIN-SUFFIX,baidupan.com,选择代理
  - DOMAIN-SUFFIX,baike.com,选择代理
  - DOMAIN-SUFFIX,biqudu.com,选择代理
  - DOMAIN-SUFFIX,biquge.com,选择代理
  - DOMAIN-SUFFIX,bitauto.com,选择代理
  - DOMAIN-SUFFIX,bosszhipin.com,选择代理
  - DOMAIN-SUFFIX,c-ctrip.com,选择代理
  - DOMAIN-SUFFIX,camera360.com,选择代理
  - DOMAIN-SUFFIX,cdnmama.com,选择代理
  - DOMAIN-SUFFIX,chaoxing.com,选择代理
  - DOMAIN-SUFFIX,che168.com,选择代理
  - DOMAIN-SUFFIX,chinacache.net,选择代理
  - DOMAIN-SUFFIX,chinaso.com,选择代理
  - DOMAIN-SUFFIX,chinaz.com,选择代理
  - DOMAIN-SUFFIX,chinaz.net,选择代理
  - DOMAIN-SUFFIX,chuimg.com,选择代理
  - DOMAIN-SUFFIX,cibntv.net,选择代理
  - DOMAIN-SUFFIX,clouddn.com,选择代理
  - DOMAIN-SUFFIX,cloudxns.net,选择代理
  - DOMAIN-SUFFIX,cn163.net,选择代理
  - DOMAIN-SUFFIX,cnblogs.com,选择代理
  - DOMAIN-SUFFIX,cnki.net,选择代理
  - DOMAIN-SUFFIX,cnmstl.net,选择代理
  - DOMAIN-SUFFIX,coolapk.com,选择代理
  - DOMAIN-SUFFIX,coolapkmarket.com,选择代理
  - DOMAIN-SUFFIX,csdn.net,选择代理
  - DOMAIN-SUFFIX,ctrip.com,选择代理
  - DOMAIN-SUFFIX,dangdang.com,选择代理
  - DOMAIN-SUFFIX,dfcfw.com,选择代理
  - DOMAIN-SUFFIX,dianping.com,选择代理
  - DOMAIN-SUFFIX,dilidili.wang,选择代理
  - DOMAIN-SUFFIX,douban.com,选择代理
  - DOMAIN-SUFFIX,doubanio.com,选择代理
  - DOMAIN-SUFFIX,dpfile.com,选择代理
  - DOMAIN-SUFFIX,duowan.com,选择代理
  - DOMAIN-SUFFIX,dxycdn.com,选择代理
  - DOMAIN-SUFFIX,dytt8.net,选择代理
  - DOMAIN-SUFFIX,easou.com,选择代理
  - DOMAIN-SUFFIX,eastday.com,选择代理
  - DOMAIN-SUFFIX,eastmoney.com,选择代理
  - DOMAIN-SUFFIX,ecitic.com,选择代理
  - DOMAIN-SUFFIX,element-plus.org,选择代理
  - DOMAIN-SUFFIX,ewqcxz.com,选择代理
  - DOMAIN-SUFFIX,fang.com,选择代理
  - DOMAIN-SUFFIX,fantasy.tv,选择代理
  - DOMAIN-SUFFIX,feng.com,选择代理
  - DOMAIN-SUFFIX,fengkongcloud.com,选择代理
  - DOMAIN-SUFFIX,fir.im,选择代理
  - DOMAIN-SUFFIX,frdic.com,选择代理
  - DOMAIN-SUFFIX,fresh-ideas.cc,选择代理
  - DOMAIN-SUFFIX,ganji.com,选择代理
  - DOMAIN-SUFFIX,ganjistatic1.com,选择代理
  - DOMAIN-SUFFIX,geetest.com,选择代理
  - DOMAIN-SUFFIX,geilicdn.com,选择代理
  - DOMAIN-SUFFIX,ghpym.com,选择代理
  - DOMAIN-SUFFIX,godic.net,选择代理
  - DOMAIN-SUFFIX,guazi.com,选择代理
  - DOMAIN-SUFFIX,gwdang.com,选择代理
  - DOMAIN-SUFFIX,gzlzfm.com,选择代理
  - DOMAIN-SUFFIX,haibian.com,选择代理
  - DOMAIN-SUFFIX,haosou.com,选择代理
  - DOMAIN-SUFFIX,hollisterco.com,选择代理
  - DOMAIN-SUFFIX,hongxiu.com,选择代理
  - DOMAIN-SUFFIX,huajiao.com,选择代理
  - DOMAIN-SUFFIX,hupu.com,选择代理
  - DOMAIN-SUFFIX,huxiucdn.com,选择代理
  - DOMAIN-SUFFIX,huya.com,选择代理
  - DOMAIN-SUFFIX,ifeng.com,选择代理
  - DOMAIN-SUFFIX,ifengimg.com,选择代理
  - DOMAIN-SUFFIX,images-amazon.com,选择代理
  - DOMAIN-SUFFIX,infzm.com,选择代理
  - DOMAIN-SUFFIX,ipip.net,选择代理
  - DOMAIN-SUFFIX,it168.com,选择代理
  - DOMAIN-SUFFIX,ithome.com,选择代理
  - DOMAIN-SUFFIX,ixdzs.com,选择代理
  - DOMAIN-SUFFIX,jianguoyun.com,选择代理
  - DOMAIN-SUFFIX,jianshu.com,选择代理
  - DOMAIN-SUFFIX,jianshu.io,选择代理
  - DOMAIN-SUFFIX,jianshuapi.com,选择代理
  - DOMAIN-SUFFIX,jiathis.com,选择代理
  - DOMAIN-SUFFIX,jmstatic.com,选择代理
  - DOMAIN-SUFFIX,jumei.com,选择代理
  - DOMAIN-SUFFIX,kaola.com,选择代理
  - DOMAIN-SUFFIX,knewone.com,选择代理
  - DOMAIN-SUFFIX,koowo.com,选择代理
  - DOMAIN-SUFFIX,koyso.com,选择代理
  - DOMAIN-SUFFIX,ksyungslb.com,选择代理
  - DOMAIN-SUFFIX,kuaidi100.com,选择代理
  - DOMAIN-SUFFIX,kugou.com,选择代理
  - DOMAIN-SUFFIX,lancdns.com,选择代理
  - DOMAIN-SUFFIX,landiannews.com,选择代理
  - DOMAIN-SUFFIX,lanzou.com,选择代理
  - DOMAIN-SUFFIX,lanzoui.com,选择代理
  - DOMAIN-SUFFIX,lanzoux.com,选择代理
  - DOMAIN-SUFFIX,lemicp.com,选择代理
  - DOMAIN-SUFFIX,letitfly.me,选择代理
  - DOMAIN-SUFFIX,lizhi.fm,选择代理
  - DOMAIN-SUFFIX,lizhi.io,选择代理
  - DOMAIN-SUFFIX,lizhifm.com,选择代理
  - DOMAIN-SUFFIX,luoo.net,选择代理
  - DOMAIN-SUFFIX,lvmama.com,选择代理
  - DOMAIN-SUFFIX,lxdns.com,选择代理
  - DOMAIN-SUFFIX,maoyan.com,选择代理
  - DOMAIN-SUFFIX,meilishuo.com,选择代理
  - DOMAIN-SUFFIX,meituan.com,选择代理
  - DOMAIN-SUFFIX,meituan.net,选择代理
  - DOMAIN-SUFFIX,meizu.com,选择代理
  - DOMAIN-SUFFIX,migucloud.com,选择代理
  - DOMAIN-SUFFIX,miguvideo.com,选择代理
  - DOMAIN-SUFFIX,mobike.com,选择代理
  - DOMAIN-SUFFIX,mogu.com,选择代理
  - DOMAIN-SUFFIX,mogucdn.com,选择代理
  - DOMAIN-SUFFIX,mogujie.com,选择代理
  - DOMAIN-SUFFIX,moji.com,选择代理
  - DOMAIN-SUFFIX,moke.com,选择代理
  - DOMAIN-SUFFIX,msstatic.com,选择代理
  - DOMAIN-SUFFIX,mubu.com,选择代理
  - DOMAIN-SUFFIX,myunlu.com,选择代理
  - DOMAIN-SUFFIX,nruan.com,选择代理
  - DOMAIN-SUFFIX,nuomi.com,选择代理
  - DOMAIN-SUFFIX,onedns.net,选择代理
  - DOMAIN-SUFFIX,oneplus.com,选择代理
  - DOMAIN-SUFFIX,onlinedown.net,选择代理
  - DOMAIN-SUFFIX,oracle.com,选择代理
  - DOMAIN-SUFFIX,oschina.net,选择代理
  - DOMAIN-SUFFIX,ourdvs.com,选择代理
  - DOMAIN-SUFFIX,polyv.net,选择代理
  - DOMAIN-SUFFIX,qbox.me,选择代理
  - DOMAIN-SUFFIX,qcloud.com,选择代理
  - DOMAIN-SUFFIX,qcloudcdn.com,选择代理
  - DOMAIN-SUFFIX,qdaily.com,选择代理
  - DOMAIN-SUFFIX,qdmm.com,选择代理
  - DOMAIN-SUFFIX,qhimg.com,选择代理
  - DOMAIN-SUFFIX,qianqian.com,选择代理
  - DOMAIN-SUFFIX,qidian.com,选择代理
  - DOMAIN-SUFFIX,qihucdn.com,选择代理
  - DOMAIN-SUFFIX,qin.io,选择代理
  - DOMAIN-SUFFIX,qiniu.com,选择代理
  - DOMAIN-SUFFIX,qiniucdn.com,选择代理
  - DOMAIN-SUFFIX,qiniudn.com,选择代理
  - DOMAIN-SUFFIX,qiushibaike.com,选择代理
  - DOMAIN-SUFFIX,quanmin.tv,选择代理
  - DOMAIN-SUFFIX,qunar.com,选择代理
  - DOMAIN-SUFFIX,qunarzz.com,选择代理
  - DOMAIN-SUFFIX,realme.com,选择代理
  - DOMAIN-SUFFIX,repaik.com,选择代理
  - DOMAIN-SUFFIX,ruguoapp.com,选择代理
  - DOMAIN-SUFFIX,runoob.com,选择代理
  - DOMAIN-SUFFIX,sankuai.com,选择代理
  - DOMAIN-SUFFIX,segmentfault.com,选择代理
  - DOMAIN-SUFFIX,sf-express.com,选择代理
  - DOMAIN-SUFFIX,shumilou.net,选择代理
  - DOMAIN-SUFFIX,simplecd.me,选择代理
  - DOMAIN-SUFFIX,smzdm.com,选择代理
  - DOMAIN-SUFFIX,snwx.com,选择代理
  - DOMAIN-SUFFIX,soufunimg.com,选择代理
  - DOMAIN-SUFFIX,sspai.com,选择代理
  - DOMAIN-SUFFIX,startssl.com,选择代理
  - DOMAIN-SUFFIX,suning.com,选择代理
  - DOMAIN-SUFFIX,synology.com,选择代理
  - DOMAIN-SUFFIX,taihe.com,选择代理
  - DOMAIN-SUFFIX,th-sjy.com,选择代理
  - DOMAIN-SUFFIX,tianqi.com,选择代理
  - DOMAIN-SUFFIX,tianqistatic.com,选择代理
  - DOMAIN-SUFFIX,tianyancha.com,选择代理
  - DOMAIN-SUFFIX,tianyaui.com,选择代理
  - DOMAIN-SUFFIX,tietuku.com,选择代理
  - DOMAIN-SUFFIX,tiexue.net,选择代理
  - DOMAIN-SUFFIX,tmiaoo.com,选择代理
  - DOMAIN-SUFFIX,trip.com,选择代理
  - DOMAIN-SUFFIX,ttmeiju.com,选择代理
  - DOMAIN-SUFFIX,tudou.com,选择代理
  - DOMAIN-SUFFIX,tuniu.com,选择代理
  - DOMAIN-SUFFIX,tuniucdn.com,选择代理
  - DOMAIN-SUFFIX,umengcloud.com,选择代理
  - DOMAIN-SUFFIX,upyun.com,选择代理
  - DOMAIN-SUFFIX,uxengine.net,选择代理
  - DOMAIN-SUFFIX,videocc.net,选择代理
  - DOMAIN-SUFFIX,vivo.com,选择代理
  - DOMAIN-SUFFIX,wandoujia.com,选择代理
  - DOMAIN-SUFFIX,weather.com,选择代理
  - DOMAIN-SUFFIX,weico.cc,选择代理
  - DOMAIN-SUFFIX,weidian.com,选择代理
  - DOMAIN-SUFFIX,weiphone.com,选择代理
  - DOMAIN-SUFFIX,weiphone.net,选择代理
  - DOMAIN-SUFFIX,womai.com,选择代理
  - DOMAIN-SUFFIX,wscdns.com,选择代理
  - DOMAIN-SUFFIX,xdrig.com,选择代理
  - DOMAIN-SUFFIX,xhscdn.com,选择代理
  - DOMAIN-SUFFIX,xiachufang.com,选择代理
  - DOMAIN-SUFFIX,xiaohongshu.com,选择代理
  - DOMAIN-SUFFIX,xiaojukeji.com,选择代理
  - DOMAIN-SUFFIX,xinhuanet.com,选择代理
  - DOMAIN-SUFFIX,xip.io,选择代理
  - DOMAIN-SUFFIX,xitek.com,选择代理
  - DOMAIN-SUFFIX,xiumi.us,选择代理
  - DOMAIN-SUFFIX,xslb.net,选择代理
  - DOMAIN-SUFFIX,xueqiu.com,选择代理
  - DOMAIN-SUFFIX,yach.me,选择代理
  - DOMAIN-SUFFIX,yeepay.com,选择代理
  - DOMAIN-SUFFIX,yhd.com,选择代理
  - DOMAIN-SUFFIX,yihaodianimg.com,选择代理
  - DOMAIN-SUFFIX,yinxiang.com,选择代理
  - DOMAIN-SUFFIX,yinyuetai.com,选择代理
  - DOMAIN-SUFFIX,yixia.com,选择代理
  - DOMAIN-SUFFIX,ys168.com,选择代理
  - DOMAIN-SUFFIX,yuewen.com,选择代理
  - DOMAIN-SUFFIX,yy.com,选择代理
  - DOMAIN-SUFFIX,yystatic.com,选择代理
  - DOMAIN-SUFFIX,zealer.com,选择代理
  - DOMAIN-SUFFIX,zhangzishi.cc,选择代理
  - DOMAIN-SUFFIX,zhanqi.tv,选择代理
  - DOMAIN-SUFFIX,zhaopin.com,选择代理
  - DOMAIN-SUFFIX,zhihu.com,选择代理
  - DOMAIN-SUFFIX,zhimg.com,选择代理
  - DOMAIN-SUFFIX,zhipin.com,选择代理
  - DOMAIN-SUFFIX,zhongsou.com,选择代理
  - DOMAIN-SUFFIX,zhuihd.com,选择代理
  - IP-CIDR,8.128.0.0/10,选择代理,no-resolve
  - IP-CIDR,8.208.0.0/12,选择代理,no-resolve
  - IP-CIDR,14.1.112.0/22,选择代理,no-resolve
  - IP-CIDR,41.222.240.0/22,选择代理,no-resolve
  - IP-CIDR,41.223.119.0/24,选择代理,no-resolve
  - IP-CIDR,43.242.168.0/22,选择代理,no-resolve
  - IP-CIDR,45.112.212.0/22,选择代理,no-resolve
  - IP-CIDR,47.52.0.0/16,选择代理,no-resolve
  - IP-CIDR,47.56.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.74.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.76.0.0/14,选择代理,no-resolve
  - IP-CIDR,47.80.0.0/12,选择代理,no-resolve
  - IP-CIDR,47.235.0.0/16,选择代理,no-resolve
  - IP-CIDR,47.236.0.0/14,选择代理,no-resolve
  - IP-CIDR,47.240.0.0/14,选择代理,no-resolve
  - IP-CIDR,47.244.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.246.0.0/16,选择代理,no-resolve
  - IP-CIDR,47.250.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.252.0.0/15,选择代理,no-resolve
  - IP-CIDR,47.254.0.0/16,选择代理,no-resolve
  - IP-CIDR,59.82.0.0/20,选择代理,no-resolve
  - IP-CIDR,59.82.240.0/21,选择代理,no-resolve
  - IP-CIDR,59.82.248.0/22,选择代理,no-resolve
  - IP-CIDR,72.254.0.0/16,选择代理,no-resolve
  - IP-CIDR,103.38.56.0/22,选择代理,no-resolve
  - IP-CIDR,103.52.76.0/22,选择代理,no-resolve
  - IP-CIDR,103.206.40.0/22,选择代理,no-resolve
  - IP-CIDR,110.76.21.0/24,选择代理,no-resolve
  - IP-CIDR,110.76.23.0/24,选择代理,no-resolve
  - IP-CIDR,112.125.0.0/17,选择代理,no-resolve
  - IP-CIDR,116.251.64.0/18,选择代理,no-resolve
  - IP-CIDR,119.38.208.0/20,选择代理,no-resolve
  - IP-CIDR,119.38.224.0/20,选择代理,no-resolve
  - IP-CIDR,119.42.224.0/20,选择代理,no-resolve
  - IP-CIDR,139.95.0.0/16,选择代理,no-resolve
  - IP-CIDR,140.205.1.0/24,选择代理,no-resolve
  - IP-CIDR,140.205.122.0/24,选择代理,no-resolve
  - IP-CIDR,147.139.0.0/16,选择代理,no-resolve
  - IP-CIDR,149.129.0.0/16,选择代理,no-resolve
  - IP-CIDR,155.102.0.0/16,选择代理,no-resolve
  - IP-CIDR,161.117.0.0/16,选择代理,no-resolve
  - IP-CIDR,163.181.0.0/16,选择代理,no-resolve
  - IP-CIDR,170.33.0.0/16,选择代理,no-resolve
  - IP-CIDR,198.11.128.0/18,选择代理,no-resolve
  - IP-CIDR,205.204.96.0/19,选择代理,no-resolve
  - IP-CIDR,19.28.0.0/23,选择代理,no-resolve
  - IP-CIDR,45.40.192.0/19,选择代理,no-resolve
  - IP-CIDR,49.51.0.0/16,选择代理,no-resolve
  - IP-CIDR,62.234.0.0/16,选择代理,no-resolve
  - IP-CIDR,94.191.0.0/17,选择代理,no-resolve
  - IP-CIDR,103.7.28.0/22,选择代理,no-resolve
  - IP-CIDR,103.116.50.0/23,选择代理,no-resolve
  - IP-CIDR,103.231.60.0/24,选择代理,no-resolve
  - IP-CIDR,109.244.0.0/16,选择代理,no-resolve
  - IP-CIDR,111.30.128.0/21,选择代理,no-resolve
  - IP-CIDR,111.30.136.0/24,选择代理,no-resolve
  - IP-CIDR,111.30.139.0/24,选择代理,no-resolve
  - IP-CIDR,111.30.140.0/23,选择代理,no-resolve
  - IP-CIDR,115.159.0.0/16,选择代理,no-resolve
  - IP-CIDR,119.28.0.0/15,选择代理,no-resolve
  - IP-CIDR,120.88.56.0/23,选择代理,no-resolve
  - IP-CIDR,121.51.0.0/16,选择代理,no-resolve
  - IP-CIDR,129.28.0.0/16,选择代理,no-resolve
  - IP-CIDR,129.204.0.0/16,选择代理,no-resolve
  - IP-CIDR,129.211.0.0/16,选择代理,no-resolve
  - IP-CIDR,132.232.0.0/16,选择代理,no-resolve
  - IP-CIDR,134.175.0.0/16,选择代理,no-resolve
  - IP-CIDR,146.56.192.0/18,选择代理,no-resolve
  - IP-CIDR,148.70.0.0/16,选择代理,no-resolve
  - IP-CIDR,150.109.0.0/16,选择代理,no-resolve
  - IP-CIDR,152.136.0.0/16,选择代理,no-resolve
  - IP-CIDR,162.14.0.0/16,选择代理,no-resolve
  - IP-CIDR,162.62.0.0/16,选择代理,no-resolve
  - IP-CIDR,170.106.130.0/24,选择代理,no-resolve
  - IP-CIDR,182.254.0.0/16,选择代理,no-resolve
  - IP-CIDR,188.131.128.0/17,选择代理,no-resolve
  - IP-CIDR,203.195.128.0/17,选择代理,no-resolve
  - IP-CIDR,203.205.128.0/17,选择代理,no-resolve
  - IP-CIDR,210.4.138.0/24,选择代理,no-resolve
  - IP-CIDR,211.152.128.0/23,选择代理,no-resolve
  - IP-CIDR,211.152.132.0/23,选择代理,no-resolve
  - IP-CIDR,211.152.148.0/23,选择代理,no-resolve
  - IP-CIDR,212.64.0.0/17,选择代理,no-resolve
  - IP-CIDR,212.129.128.0/17,选择代理,no-resolve
  - IP-CIDR,45.113.192.0/22,选择代理,no-resolve
  - IP-CIDR,63.217.23.0/24,选择代理,no-resolve
  - IP-CIDR,63.243.252.0/24,选择代理,no-resolve
  - IP-CIDR,103.235.44.0/22,选择代理,no-resolve
  - IP-CIDR,104.193.88.0/22,选择代理,no-resolve
  - IP-CIDR,106.12.0.0/15,选择代理,no-resolve
  - IP-CIDR,114.28.224.0/20,选择代理,no-resolve
  - IP-CIDR,119.63.192.0/21,选择代理,no-resolve
  - IP-CIDR,180.76.0.0/24,选择代理,no-resolve
  - IP-CIDR,180.76.0.0/16,选择代理,no-resolve
  - IP-CIDR,182.61.0.0/16,选择代理,no-resolve
  - IP-CIDR,185.10.104.0/22,选择代理,no-resolve
  - IP-CIDR,202.46.48.0/20,选择代理,no-resolve
  - IP-CIDR,203.90.238.0/24,选择代理,no-resolve
  - IP-CIDR,43.254.0.0/22,选择代理,no-resolve
  - IP-CIDR,45.249.212.0/22,选择代理,no-resolve
  - IP-CIDR,49.4.0.0/17,选择代理,no-resolve
  - IP-CIDR,78.101.192.0/19,选择代理,no-resolve
  - IP-CIDR,78.101.224.0/20,选择代理,no-resolve
  - IP-CIDR,81.52.161.0/24,选择代理,no-resolve
  - IP-CIDR,85.97.220.0/22,选择代理,no-resolve
  - IP-CIDR,103.31.200.0/22,选择代理,no-resolve
  - IP-CIDR,103.69.140.0/23,选择代理,no-resolve
  - IP-CIDR,103.218.216.0/22,选择代理,no-resolve
  - IP-CIDR,114.115.128.0/17,选择代理,no-resolve
  - IP-CIDR,114.116.0.0/16,选择代理,no-resolve
  - IP-CIDR,116.63.128.0/18,选择代理,no-resolve
  - IP-CIDR,116.66.184.0/22,选择代理,no-resolve
  - IP-CIDR,116.71.96.0/20,选择代理,no-resolve
  - IP-CIDR,116.71.128.0/21,选择代理,no-resolve
  - IP-CIDR,116.71.136.0/22,选择代理,no-resolve
  - IP-CIDR,116.71.141.0/24,选择代理,no-resolve
  - IP-CIDR,116.71.142.0/24,选择代理,no-resolve
  - IP-CIDR,116.71.243.0/24,选择代理,no-resolve
  - IP-CIDR,116.71.244.0/24,选择代理,no-resolve
  - IP-CIDR,116.71.251.0/24,选择代理,no-resolve
  - IP-CIDR,117.78.0.0/18,选择代理,no-resolve
  - IP-CIDR,119.3.0.0/16,选择代理,no-resolve
  - IP-CIDR,119.8.0.0/21,选择代理,no-resolve
  - IP-CIDR,119.8.32.0/19,选择代理,no-resolve
  - IP-CIDR,121.36.0.0/17,选择代理,no-resolve
  - IP-CIDR,121.36.128.0/18,选择代理,no-resolve
  - IP-CIDR,121.37.0.0/17,选择代理,no-resolve
  - IP-CIDR,122.112.128.0/17,选择代理,no-resolve
  - IP-CIDR,139.9.0.0/18,选择代理,no-resolve
  - IP-CIDR,139.9.64.0/19,选择代理,no-resolve
  - IP-CIDR,139.9.100.0/22,选择代理,no-resolve
  - IP-CIDR,139.9.104.0/21,选择代理,no-resolve
  - IP-CIDR,139.9.112.0/20,选择代理,no-resolve
  - IP-CIDR,139.9.128.0/18,选择代理,no-resolve
  - IP-CIDR,139.9.192.0/19,选择代理,no-resolve
  - IP-CIDR,139.9.224.0/20,选择代理,no-resolve
  - IP-CIDR,139.9.240.0/21,选择代理,no-resolve
  - IP-CIDR,139.9.248.0/22,选择代理,no-resolve
  - IP-CIDR,139.159.128.0/19,选择代理,no-resolve
  - IP-CIDR,139.159.160.0/22,选择代理,no-resolve
  - IP-CIDR,139.159.164.0/23,选择代理,no-resolve
  - IP-CIDR,139.159.168.0/21,选择代理,no-resolve
  - IP-CIDR,139.159.176.0/20,选择代理,no-resolve
  - IP-CIDR,139.159.192.0/18,选择代理,no-resolve
  - IP-CIDR,159.138.0.0/18,选择代理,no-resolve
  - IP-CIDR,159.138.64.0/21,选择代理,no-resolve
  - IP-CIDR,159.138.79.0/24,选择代理,no-resolve
  - IP-CIDR,159.138.80.0/20,选择代理,no-resolve
  - IP-CIDR,159.138.96.0/20,选择代理,no-resolve
  - IP-CIDR,159.138.112.0/21,选择代理,no-resolve
  - IP-CIDR,159.138.125.0/24,选择代理,no-resolve
  - IP-CIDR,159.138.128.0/18,选择代理,no-resolve
  - IP-CIDR,159.138.192.0/20,选择代理,no-resolve
  - IP-CIDR,159.138.223.0/24,选择代理,no-resolve
  - IP-CIDR,159.138.224.0/19,选择代理,no-resolve
  - IP-CIDR,168.195.92.0/22,选择代理,no-resolve
  - IP-CIDR,185.176.76.0/22,选择代理,no-resolve
  - IP-CIDR,197.199.0.0/18,选择代理,no-resolve
  - IP-CIDR,197.210.163.0/24,选择代理,no-resolve
  - IP-CIDR,197.252.1.0/24,选择代理,no-resolve
  - IP-CIDR,197.252.2.0/23,选择代理,no-resolve
  - IP-CIDR,197.252.4.0/22,选择代理,no-resolve
  - IP-CIDR,197.252.8.0/21,选择代理,no-resolve
  - IP-CIDR,200.32.52.0/24,选择代理,no-resolve
  - IP-CIDR,200.32.54.0/24,选择代理,no-resolve
  - IP-CIDR,200.32.57.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.0.0/22,选择代理,no-resolve
  - IP-CIDR,203.135.4.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.8.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.11.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.13.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.20.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.22.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.24.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.26.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.29.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.33.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.38.0/23,选择代理,no-resolve
  - IP-CIDR,203.135.40.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.43.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.48.0/24,选择代理,no-resolve
  - IP-CIDR,203.135.50.0/24,选择代理,no-resolve
  - IP-CIDR,42.186.0.0/16,选择代理,no-resolve
  - IP-CIDR,45.127.128.0/22,选择代理,no-resolve
  - IP-CIDR,45.195.24.0/24,选择代理,no-resolve
  - IP-CIDR,45.253.132.0/22,选择代理,no-resolve
  - IP-CIDR,45.253.240.0/22,选择代理,no-resolve
  - IP-CIDR,45.254.48.0/23,选择代理,no-resolve
  - IP-CIDR,59.111.0.0/20,选择代理,no-resolve
  - IP-CIDR,59.111.128.0/17,选择代理,no-resolve
  - IP-CIDR,103.71.120.0/21,选择代理,no-resolve
  - IP-CIDR,103.71.128.0/22,选择代理,no-resolve
  - IP-CIDR,103.71.196.0/22,选择代理,no-resolve
  - IP-CIDR,103.71.200.0/22,选择代理,no-resolve
  - IP-CIDR,103.72.12.0/22,选择代理,no-resolve
  - IP-CIDR,103.72.18.0/23,选择代理,no-resolve
  - IP-CIDR,103.72.24.0/22,选择代理,no-resolve
  - IP-CIDR,103.72.28.0/23,选择代理,no-resolve
  - IP-CIDR,103.72.38.0/23,选择代理,no-resolve
  - IP-CIDR,103.72.40.0/23,选择代理,no-resolve
  - IP-CIDR,103.72.44.0/22,选择代理,no-resolve
  - IP-CIDR,103.72.48.0/21,选择代理,no-resolve
  - IP-CIDR,103.72.128.0/21,选择代理,no-resolve
  - IP-CIDR,103.74.24.0/21,选择代理,no-resolve
  - IP-CIDR,103.74.48.0/22,选择代理,no-resolve
  - IP-CIDR,103.126.92.0/22,选择代理,no-resolve
  - IP-CIDR,103.129.252.0/22,选择代理,no-resolve
  - IP-CIDR,103.131.252.0/22,选择代理,no-resolve
  - IP-CIDR,103.135.240.0/22,选择代理,no-resolve
  - IP-CIDR,103.196.64.0/22,选择代理,no-resolve
  - IP-CIDR,106.2.32.0/19,选择代理,no-resolve
  - IP-CIDR,106.2.64.0/18,选择代理,no-resolve
  - IP-CIDR,114.113.196.0/22,选择代理,no-resolve
  - IP-CIDR,114.113.200.0/22,选择代理,no-resolve
  - IP-CIDR,115.236.112.0/20,选择代理,no-resolve
  - IP-CIDR,115.238.76.0/22,选择代理,no-resolve
  - IP-CIDR,123.58.160.0/19,选择代理,no-resolve
  - IP-CIDR,223.252.192.0/19,选择代理,no-resolve
  - IP-CIDR,101.198.128.0/18,选择代理,no-resolve
  - IP-CIDR,101.198.192.0/19,选择代理,no-resolve
  - IP-CIDR,101.199.196.0/22,选择代理,no-resolve
  - DOMAIN,p-bstarstatic.akamaized.net,📺哔哩哔哩
  - DOMAIN,p.bstarstatic.com,📺哔哩哔哩
  - DOMAIN,upos-bstar-mirrorakam.akamaized.net,📺哔哩哔哩
  - DOMAIN,upos-bstar1-mirrorakam.akamaized.net,📺哔哩哔哩
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,📺哔哩哔哩
  - DOMAIN-SUFFIX,acgvideo.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.tv,📺哔哩哔哩
  - IP-CIDR,45.43.32.234/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,103.151.150.0/23,📺哔哩哔哩,no-resolve
  - IP-CIDR,119.29.29.29/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,128.1.62.200/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,128.1.62.201/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,150.116.92.250/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,164.52.33.178/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,164.52.33.182/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,164.52.76.18/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,203.107.1.33/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,203.107.1.34/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,203.107.1.65/32,📺哔哩哔哩,no-resolve
  - IP-CIDR,203.107.1.66/32,📺哔哩哔哩,no-resolve
  - DOMAIN,apiintl.biliapi.net,📺哔哩哔哩
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,📺哔哩哔哩
  - DOMAIN-SUFFIX,acg.tv,📺哔哩哔哩
  - DOMAIN-SUFFIX,acgvideo.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,b23.tv,📺哔哩哔哩
  - DOMAIN-SUFFIX,bigfun.cn,📺哔哩哔哩
  - DOMAIN-SUFFIX,bigfunapp.cn,📺哔哩哔哩
  - DOMAIN-SUFFIX,biliapi.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,biliapi.net,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.co,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilibili.tv,📺哔哩哔哩
  - DOMAIN-SUFFIX,biligame.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,biligame.net,📺哔哩哔哩
  - DOMAIN-SUFFIX,biliintl.co,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilivideo.cn,📺哔哩哔哩
  - DOMAIN-SUFFIX,bilivideo.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,hdslb.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,im9.com,📺哔哩哔哩
  - DOMAIN-SUFFIX,smtcdns.net,📺哔哩哔哩
  - DOMAIN,cloudflare.com,选择代理
  - DOMAIN,dash.cloudfare.com,选择代理
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,选择代理`
}
		
function getpsbConfig(userID, hostName) {
return `{
		  "log": {
			"disabled": false,
			"level": "info",
			"timestamp": true
		  },
		  "experimental": {
			"clash_api": {
			  "external_controller": "127.0.0.1:9090",
			  "external_ui": "ui",
			  "external_ui_download_url": "",
			  "external_ui_download_detour": "",
			  "secret": "",
			  "default_mode": "Rule"
			},
			"cache_file": {
			  "enabled": true,
			  "path": "cache.db",
			  "store_fakeip": true
			}
		  },
		  "dns": {
			"servers": [
			  {
				"tag": "proxydns",
				"address": "tls://8.8.8.8/dns-query",
				"detour": "select"
			  },
			  {
				"tag": "localdns",
				"address": "h3://223.5.5.5/dns-query",
				"detour": "direct"
			  },
			  {
				"address": "rcode://refused",
				"tag": "block"
			  },
			  {
				"tag": "dns_fakeip",
				"address": "fakeip"
			  }
			],
			"rules": [
			  {
				"outbound": "any",
				"server": "localdns",
				"disable_cache": true
			  },
			  {
				"clash_mode": "Global",
				"server": "proxydns"
			  },
			  {
				"clash_mode": "Direct",
				"server": "localdns"
			  },
			  {
				"rule_set": "geosite-cn",
				"server": "localdns"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"server": "proxydns"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"query_type": [
				  "A",
				  "AAAA"
				],
				"server": "dns_fakeip"
			  }
			],
			"fakeip": {
			  "enabled": true,
			  "inet4_range": "198.18.0.0/15",
			  "inet6_range": "fc00::/18"
			},
			"independent_cache": true,
			"final": "proxydns"
		  },
		  "inbounds": [
			{
			  "type": "tun",
			  "inet4_address": "172.19.0.1/30",
			  "inet6_address": "fd00::1/126",
			  "auto_route": true,
			  "strict_route": true,
			  "sniff": true,
			  "sniff_override_destination": true,
			  "domain_strategy": "prefer_ipv4"
			}
		  ],
		  "outbounds": [
			{
			  "tag": "select",
			  "type": "selector",
			  "default": "auto",
			  "outbounds": [
				"auto",
				"CF_V8_${IP8}_${PT8}",
				"CF_V9_${IP9}_${PT9}",
				"CF_V10_${IP10}_${PT10}",
				"CF_V11_${IP11}_${PT11}",
				"CF_V12_${IP12}_${PT12}",
				"CF_V13_${IP13}_${PT13}"
			  ]
			},
			{
			  "server": "${IP8}",
			  "server_port": ${PT8},
			  "tag": "CF_V8_${IP8}_${PT8}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP9}",
			  "server_port": ${PT9},
			  "tag": "CF_V9_${IP9}_${PT9}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP10}",
			  "server_port": ${PT10},
			  "tag": "CF_V10_${IP10}_${PT10}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP11}",
			  "server_port": ${PT11},
			  "tag": "CF_V11_${IP11}_${PT11}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP12}",
			  "server_port": ${PT12},
			  "tag": "CF_V12_${IP12}_${PT12}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP13}",
			  "server_port": ${PT13},
			  "tag": "CF_V13_${IP13}_${PT13}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "tag": "direct",
			  "type": "direct"
			},
			{
			  "tag": "block",
			  "type": "block"
			},
			{
			  "tag": "dns-out",
			  "type": "dns"
			},
			{
			  "tag": "auto",
			  "type": "urltest",
			  "outbounds": [
				"CF_V8_${IP8}_${PT8}",
				"CF_V9_${IP9}_${PT9}",
				"CF_V10_${IP10}_${PT10}",
				"CF_V11_${IP11}_${PT11}",
				"CF_V12_${IP12}_${PT12}",
				"CF_V13_${IP13}_${PT13}"
			  ],
			  "url": "https://www.gstatic.com/generate_204",
			  "interval": "1m",
			  "tolerance": 50,
			  "interrupt_exist_connections": false
			}
		  ],
		  "route": {
			"rule_set": [
			  {
				"tag": "geosite-geolocation-!cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  },
			  {
				"tag": "geosite-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  },
			  {
				"tag": "geoip-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  }
			],
			"auto_detect_interface": true,
			"final": "select",
			"rules": [
			  {
				"outbound": "dns-out",
				"protocol": "dns"
			  },
			  {
				"clash_mode": "Direct",
				"outbound": "direct"
			  },
			  {
				"clash_mode": "Global",
				"outbound": "select"
			  },
			  {
				"rule_set": "geoip-cn",
				"outbound": "direct"
			  },
			  {
				"rule_set": "geosite-cn",
				"outbound": "direct"
			  },
			  {
				"ip_is_private": true,
				"outbound": "direct"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"outbound": "select"
			  }
			]
		  },
		  "ntp": {
			"enabled": true,
			"server": "time.apple.com",
			"server_port": 123,
			"interval": "30m",
			"detour": "direct"
		  }
		}`;
} 