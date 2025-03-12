import { connect } from "cloudflare:sockets";
 
let Pswd = "trojan";
const proxyIPs = ["\u0074\u0073\u002e\u0068\u0070\u0063\u002e\u0074\u0077"]; 
let cn_hostnames = [''];
let CDNIP = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'

let IP1 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP2 = '\u0063\u0069\u0073\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP3 = '\u0061\u0066\u0072\u0069\u0063\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP4 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
let IP5 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0061\u0074'
let IP6 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u006d\u0074'
let IP7 = '\u0071\u0061\u002e\u0076\u0069\u0073\u0061\u006d\u0069\u0064\u0064\u006c\u0065\u0065\u0061\u0073\u0074\u002e\u0063\u006f\u006d'

let IP8 = '\u0075\u0073\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP9 = '\u006d\u0079\u0061\u006e\u006d\u0061\u0072\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP10 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0074\u0077'
let IP11 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u0068'
let IP12 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0062\u0072'
let IP13 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0073\u006f\u0075\u0074\u0068\u0065\u0061\u0073\u0074\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u006f\u006d'

let PT1 = '80'
let PT2 = '8080'
let PT3 = '8880'
let PT4 = '2052'
let PT5 = '2082'
let PT6 = '2086'
let PT7 = '2095'

let PT8 = '443'
let PT9 = '8443'
let PT10 = '2053'
let PT11 = '2083'
let PT12 = '2087'
let PT13 = '2096'

let sha224Password;
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let proxyPort = proxyIP.includes(':') ? proxyIP.split(':')[1] : '443';
const worker_default = {
  async fetch(request, env, ctx) {
    try {
      const { proxyip } = env;
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
      Pswd = env.pswd || Pswd;
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
      sha224Password = sha256.sha224(Pswd);
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const url = new URL(request.url);
        switch (url.pathname) {
          case `/${Pswd}`: {
            const trojanConfig = gettrojanConfig(Pswd, request.headers.get("Host"));
            return new Response(`${trojanConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/html;charset=utf-8",
              },
            });
          }
		  case `/${Pswd}/ty`: {
			const tyConfig = gettyConfig(Pswd, request.headers.get('Host'));
			return new Response(`${tyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/cl`: {
			const clConfig = getclConfig(Pswd, request.headers.get('Host'));
			return new Response(`${clConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/sb`: {
			const sbConfig = getsbConfig(Pswd, request.headers.get('Host'));
			return new Response(`${sbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/pty`: {
			const ptyConfig = getptyConfig(Pswd, request.headers.get('Host'));
			return new Response(`${ptyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/pcl`: {
			const pclConfig = getpclConfig(Pswd, request.headers.get('Host'));
			return new Response(`${pclConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/psb`: {
			const psbConfig = getpsbConfig(Pswd, request.headers.get('Host'));
			return new Response(`${psbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
          default:
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
            const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual",
            });
            const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                status: 403,
                statusText: "Forbidden",
              });
            }
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
        return await trojanOverWSHandler(request);
		}
    } catch (err) {
       let e = err;
      return new Response(e.toString());
    }
  },
};

function isValidIP(ip) {
    var reg = /^[\s\S]*$/;
    return reg.test(ip);
}

async function trojanOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = {
    value: null,
  };
  let udpStreamWrite = null;
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (udpStreamWrite) {
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
            rawClientData,
          } = await parseTrojanHeader(chunk);
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
          if (hasError) {
            throw new Error(message);
            return;
          }
          handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
        },
        close() {
          log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
          log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });
  return new Response(null, {
    status: 101,
    
    webSocket: client,
  });
}

async function parseTrojanHeader(buffer) {
  if (buffer.byteLength < 56) {
    return {
      hasError: true,
      message: "invalid data",
    };
  }
  let crLfIndex = 56;
  if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
    return {
      hasError: true,
      message: "invalid header format (missing CR LF)",
    };
  }
  const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
  if (password !== sha224Password) {
    return {
      hasError: true,
      message: "invalid password",
    };
  }
  const socks5DataBuffer = buffer.slice(crLfIndex + 2);
  if (socks5DataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid SOCKS5 request data",
    };
  }
  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd !== 1) {
    return {
      hasError: true,
      message: "unsupported command, only TCP (CONNECT) is allowed",
    };
  }
  const atype = view.getUint8(1);
  let addressLength = 0;
  let addressIndex = 2;
  let address = "";
  switch (atype) {
    case 1:
      addressLength = 4;
      address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
      addressIndex += 1;
      address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      address = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${atype}`,
      };
  }
  if (!address) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${atype}`,
    };
  }
  const portIndex = addressIndex + addressLength;
  const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: address,
    portRemote,
    rawClientData: socks5DataBuffer.slice(portIndex + 4),
  };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(addressRemote)) addressRemote = `${atob('d3d3Lg==')}${addressRemote}${atob('LnNzbGlwLmlv')}`;
  async function connectAndWrite(address, port) {
    const tcpSocket2 = connect({
      hostname: address,
      port,
    });
    remoteSocket.value = tcpSocket2;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  async function retry() {
    const tcpSocket2 = await connectAndWrite(proxyIP || addressRemote, proxyPort || portRemote);
    tcpSocket2.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket2, webSocket, null, log);
  }
  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

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
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`readableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
  return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket connection is not open");
          }
          webSocket.send(chunk);
        },
        close() {
          log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error("remoteSocket.readable abort", reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS error:`, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

let WS_READY_STATE_OPEN = 1;
let WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}
export { worker_default as default };

function gettyConfig(Pswd, hostName) {
  const trojanshare = btoa(`trojan://${Pswd}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T1_${IP1}_${PT1}\ntrojan://${Pswd}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T2_${IP2}_${PT2}\ntrojan://${Pswd}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T3_${IP3}_${PT3}\ntrojan://${Pswd}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T4_${IP4}_${PT4}\ntrojan://${Pswd}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T5_${IP5}_${PT5}\ntrojan://${Pswd}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T6_${IP6}_${PT6}\ntrojan://${Pswd}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T7_${IP7}_${PT7}\ntrojan://${Pswd}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T8_${IP8}_${PT8}\ntrojan://${Pswd}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T9_${IP9}_${PT9}\ntrojan://${Pswd}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T10_${IP10}_${PT10}\ntrojan://${Pswd}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T11_${IP11}_${PT11}\ntrojan://${Pswd}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T12_${IP12}_${PT12}\ntrojan://${Pswd}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T13_${IP13}_${PT13}`);
  return `${trojanshare}`
}

function getclConfig(Pswd, hostName) {
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
- name: CF_T8_${IP8}_${PT8}
  type: trojan
  server: ${IP8}
  port: ${PT8}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T9_${IP9}_${PT9}
  type: trojan
  server: ${IP9}
  port: ${PT9}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T10_${IP10}_${PT10}
  type: trojan
  server: ${IP10}
  port: ${PT10}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T11_${IP11}_${PT11}
  type: trojan
  server: ${IP11}
  port: ${PT11}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T12_${IP12}_${PT12}
  type: trojan
  server: ${IP12}
  port: ${PT12}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T13_${IP13}_${PT13}
  type: trojan
  server: ${IP13}
  port: ${PT13}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: LAX1
  type: trojan
  server: 104.21.198.62
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: LAX2
  type: trojan
  server: 162.159.45.219
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: HKG1
  type: trojan
  server: 104.20.206.24
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: AMS
  type: trojan
  server: 162.159.160.204
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: LHR
  type: trojan
  server: 162.159.81.154
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: TW
  type: trojan
  server: 210.61.97.241
  port: 81
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: LOAD
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}
    - LAX1
    - LAX2
    - HKG1
    - AMS
    - LHR
    - TW

- name: AUTO
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}
    - LAX1
    - LAX2
    - HKG1
    - AMS
    - LHR
    - TW

- name: SELECT
  type: select
  proxies:
    - LOAD
    - AUTO
    - DIRECT
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}
    - LAX1
    - LAX2
    - HKG1
    - AMS
    - LHR
    - TW

- name: BILI
  type: select
  url: https://www.bilibili.com/
  proxies:
    - DIRECT
    - SELECT
    - HKG1
    - TW

- name: DC
  type: select
  proxies:
    - DIRECT
    - AUTO
    - SELECT

- name: AD-BAN
  type: select
  proxies:
    - REJECT
    - DIRECT

rules:
  - PROCESS-NAME,cfnat-android-arm64,DC
  - PROCESS-NAME,cfnat-darwin-amd64,DC
  - PROCESS-NAME,cfnat-darwin-arm64,DC
  - PROCESS-NAME,cfnat-dragonfly-amd64,DC
  - PROCESS-NAME,cfnat-freebsd-386,DC
  - PROCESS-NAME,cfnat-freebsd-amd64,DC
  - PROCESS-NAME,cfnat-freebsd-arm,DC
  - PROCESS-NAME,cfnat-freebsd-arm64,DC
  - PROCESS-NAME,cfnat-linux-386,DC
  - PROCESS-NAME,cfnat-linux-amd64,DC
  - PROCESS-NAME,cfnat-linux-arm,DC
  - PROCESS-NAME,cfnat-linux-arm64,DC
  - PROCESS-NAME,cfnat-linux-mips,DC
  - PROCESS-NAME,cfnat-linux-mips64,DC
  - PROCESS-NAME,cfnat-linux-mips64le,DC
  - PROCESS-NAME,cfnat-linux-mipsle,DC
  - PROCESS-NAME,cfnat-linux-ppc64,DC
  - PROCESS-NAME,cfnat-linux-ppc64le,DC
  - PROCESS-NAME,cfnat-linux-riscv64,DC
  - PROCESS-NAME,cfnat-linux-s390x,DC
  - PROCESS-NAME,cfnat-netbsd-386,DC
  - PROCESS-NAME,cfnat-netbsd-amd64,DC
  - PROCESS-NAME,cfnat-netbsd-arm,DC
  - PROCESS-NAME,cfnat-netbsd-arm64,DC
  - PROCESS-NAME,cfnat-openbsd-386,DC
  - PROCESS-NAME,cfnat-openbsd-amd64,DC
  - PROCESS-NAME,cfnat-openbsd-arm,DC
  - PROCESS-NAME,cfnat-openbsd-arm64,DC
  - PROCESS-NAME,cfnat-plan9-386,DC
  - PROCESS-NAME,cfnat-plan9-amd64,DC
  - PROCESS-NAME,cfnat-solaris-amd64,DC
  - PROCESS-NAME,cfnat-termux,DC
  - PROCESS-NAME,cfnat-windows-386.exe,DC
  - PROCESS-NAME,cfnat-windows-amd64.exe,DC
  - PROCESS-NAME,cfnat-windows-arm.exe,DC
  - PROCESS-NAME,cfnat-windows-arm64.exe,DC
  - PROCESS-NAME,cfnat-windows7-386.exe,DC
  - PROCESS-NAME,cfnat-windows7-amd64.exe,DC
  - PROCESS-NAME,colo-android-arm64,DC
  - PROCESS-NAME,colo-darwin-amd64,DC
  - PROCESS-NAME,colo-darwin-arm64,DC
  - PROCESS-NAME,colo-dragonfly-amd64,DC
  - PROCESS-NAME,colo-freebsd-386,DC
  - PROCESS-NAME,colo-freebsd-amd64,DC
  - PROCESS-NAME,colo-freebsd-arm,DC
  - PROCESS-NAME,colo-freebsd-arm64,DC
  - PROCESS-NAME,colo-linux-386,DC
  - PROCESS-NAME,colo-linux-amd64,DC
  - PROCESS-NAME,colo-linux-arm,DC
  - PROCESS-NAME,colo-linux-arm64,DC
  - PROCESS-NAME,colo-linux-mips,DC
  - PROCESS-NAME,colo-linux-mips64,DC
  - PROCESS-NAME,colo-linux-mips64le,DC
  - PROCESS-NAME,colo-linux-mipsle,DC
  - PROCESS-NAME,colo-linux-ppc64,DC
  - PROCESS-NAME,colo-linux-ppc64le,DC
  - PROCESS-NAME,colo-linux-riscv64,DC
  - PROCESS-NAME,colo-linux-s390x,DC
  - PROCESS-NAME,colo-netbsd-386,DC
  - PROCESS-NAME,colo-netbsd-amd64,DC
  - PROCESS-NAME,colo-netbsd-arm,DC
  - PROCESS-NAME,colo-netbsd-arm64,DC
  - PROCESS-NAME,colo-openbsd-386,DC
  - PROCESS-NAME,colo-openbsd-amd64,DC
  - PROCESS-NAME,colo-openbsd-arm,DC
  - PROCESS-NAME,colo-openbsd-arm64,DC
  - PROCESS-NAME,colo-plan9-386,DC
  - PROCESS-NAME,colo-plan9-amd64,DC
  - PROCESS-NAME,colo-solaris-amd64,DC
  - PROCESS-NAME,colo-windows-386.exe,DC
  - PROCESS-NAME,colo-windows-amd64.exe,DC
  - PROCESS-NAME,colo-windows-arm.exe,DC
  - PROCESS-NAME,colo-windows-arm64.exe,DC
  - DOMAIN-SUFFIX,acl4.ssr,DC
  - DOMAIN-SUFFIX,ip6-localhost,DC
  - DOMAIN-SUFFIX,ip6-loopback,DC
  - DOMAIN-SUFFIX,lan,DC
  - DOMAIN-SUFFIX,local,DC
  - DOMAIN-SUFFIX,localhost,DC
  - IP-CIDR,0.0.0.0/8,DC,no-resolve
  - IP-CIDR,10.0.0.0/8,DC,no-resolve
  - IP-CIDR,100.64.0.0/10,DC,no-resolve
  - IP-CIDR,127.0.0.0/8,DC,no-resolve
  - IP-CIDR,172.16.0.0/12,DC,no-resolve
  - IP-CIDR,192.168.0.0/16,DC,no-resolve
  - IP-CIDR,198.18.0.0/16,DC,no-resolve
  - IP-CIDR,224.0.0.0/4,DC,no-resolve
  - IP-CIDR6,::1/128,DC,no-resolve
  - IP-CIDR6,fc00::/7,DC,no-resolve
  - IP-CIDR6,fe80::/10,DC,no-resolve
  - IP-CIDR6,fd00::/8,DC,no-resolve
  - DOMAIN,instant.arubanetworks.com,DC
  - DOMAIN,setmeup.arubanetworks.com,DC
  - DOMAIN,router.asus.com,DC
  - DOMAIN,www.asusrouter.com,DC
  - DOMAIN-SUFFIX,hiwifi.com,DC
  - DOMAIN-SUFFIX,leike.cc,DC
  - DOMAIN-SUFFIX,miwifi.com,DC
  - DOMAIN-SUFFIX,my.router,DC
  - DOMAIN-SUFFIX,p.to,DC
  - DOMAIN-SUFFIX,peiluyou.com,DC
  - DOMAIN-SUFFIX,phicomm.me,DC
  - DOMAIN-SUFFIX,router.ctc,DC
  - DOMAIN-SUFFIX,routerlogin.com,DC
  - DOMAIN-SUFFIX,tendawifi.com,DC
  - DOMAIN-SUFFIX,zte.home,DC
  - DOMAIN-SUFFIX,tplogin.cn,DC
  - DOMAIN-SUFFIX,wifi.cmcc,DC
  - DOMAIN-SUFFIX,ol.epicgames.com,DC
  - DOMAIN-SUFFIX,dizhensubao.getui.com,DC
  - DOMAIN,dl.google.com,DC
  - DOMAIN-SUFFIX,googletraveladservices.com,DC
  - DOMAIN-SUFFIX,tracking-protection.cdn.mozilla.net,DC
  - DOMAIN,origin-a.akamaihd.net,DC
  - DOMAIN,fairplay.l.qq.com,DC
  - DOMAIN,livew.l.qq.com,DC
  - DOMAIN,vd.l.qq.com,DC
  - DOMAIN,errlog.umeng.com,DC
  - DOMAIN,msg.umeng.com,DC
  - DOMAIN,msg.umengcloud.com,DC
  - DOMAIN,tracking.miui.com,DC
  - DOMAIN,app.adjust.com,DC
  - DOMAIN,bdtj.tagtic.cn,DC
  - DOMAIN,rewards.hypixel.net,DC
  - DOMAIN-SUFFIX,koodomobile.com,DC
  - DOMAIN-SUFFIX,koodomobile.ca,DC
  - DOMAIN-KEYWORD,admarvel,AD-BAN
  - DOMAIN-KEYWORD,admaster,AD-BAN
  - DOMAIN-KEYWORD,adsage,AD-BAN
  - DOMAIN-KEYWORD,adsensor,AD-BAN
  - DOMAIN-KEYWORD,adsmogo,AD-BAN
  - DOMAIN-KEYWORD,adsrvmedia,AD-BAN
  - DOMAIN-KEYWORD,adsserving,AD-BAN
  - DOMAIN-KEYWORD,adsystem,AD-BAN
  - DOMAIN-KEYWORD,adwords,AD-BAN
  - DOMAIN-KEYWORD,applovin,AD-BAN
  - DOMAIN-KEYWORD,appsflyer,AD-BAN
  - DOMAIN-KEYWORD,domob,AD-BAN
  - DOMAIN-KEYWORD,duomeng,AD-BAN
  - DOMAIN-KEYWORD,dwtrack,AD-BAN
  - DOMAIN-KEYWORD,guanggao,AD-BAN
  - DOMAIN-KEYWORD,omgmta,AD-BAN
  - DOMAIN-KEYWORD,omniture,AD-BAN
  - DOMAIN-KEYWORD,openx,AD-BAN
  - DOMAIN-KEYWORD,partnerad,AD-BAN
  - DOMAIN-KEYWORD,pingfore,AD-BAN
  - DOMAIN-KEYWORD,socdm,AD-BAN
  - DOMAIN-KEYWORD,supersonicads,AD-BAN
  - DOMAIN-KEYWORD,wlmonitor,AD-BAN
  - DOMAIN-KEYWORD,zjtoolbar,AD-BAN
  - DOMAIN-SUFFIX,09mk.cn,AD-BAN
  - DOMAIN-SUFFIX,100peng.com,AD-BAN
  - DOMAIN-SUFFIX,114la.com,AD-BAN
  - DOMAIN-SUFFIX,123juzi.net,AD-BAN
  - DOMAIN-SUFFIX,138lm.com,AD-BAN
  - DOMAIN-SUFFIX,17un.com,AD-BAN
  - DOMAIN-SUFFIX,2cnt.net,AD-BAN
  - DOMAIN-SUFFIX,3gmimo.com,AD-BAN
  - DOMAIN-SUFFIX,3xx.vip,AD-BAN
  - DOMAIN-SUFFIX,51.la,AD-BAN
  - DOMAIN-SUFFIX,51taifu.com,AD-BAN
  - DOMAIN-SUFFIX,51yes.com,AD-BAN
  - DOMAIN-SUFFIX,600ad.com,AD-BAN
  - DOMAIN-SUFFIX,6dad.com,AD-BAN
  - DOMAIN-SUFFIX,70e.com,AD-BAN
  - DOMAIN-SUFFIX,86.cc,AD-BAN
  - DOMAIN-SUFFIX,8le8le.com,AD-BAN
  - DOMAIN-SUFFIX,8ox.cn,AD-BAN
  - DOMAIN-SUFFIX,95558000.com,AD-BAN
  - DOMAIN-SUFFIX,99click.com,AD-BAN
  - DOMAIN-SUFFIX,99youmeng.com,AD-BAN
  - DOMAIN-SUFFIX,a3p4.net,AD-BAN
  - DOMAIN-SUFFIX,acs86.com,AD-BAN
  - DOMAIN-SUFFIX,acxiom-online.com,AD-BAN
  - DOMAIN-SUFFIX,ad-brix.com,AD-BAN
  - DOMAIN-SUFFIX,ad-delivery.net,AD-BAN
  - DOMAIN-SUFFIX,ad-locus.com,AD-BAN
  - DOMAIN-SUFFIX,ad-plus.cn,AD-BAN
  - DOMAIN-SUFFIX,ad7.com,AD-BAN
  - DOMAIN-SUFFIX,adadapted.com,AD-BAN
  - DOMAIN-SUFFIX,adadvisor.net,AD-BAN
  - DOMAIN-SUFFIX,adap.tv,AD-BAN
  - DOMAIN-SUFFIX,adbana.com,AD-BAN
  - DOMAIN-SUFFIX,adchina.com,AD-BAN
  - DOMAIN-SUFFIX,adcome.cn,AD-BAN
  - DOMAIN-SUFFIX,ader.mobi,AD-BAN
  - DOMAIN-SUFFIX,adform.net,AD-BAN
  - DOMAIN-SUFFIX,adfuture.cn,AD-BAN
  - DOMAIN-SUFFIX,adhouyi.com,AD-BAN
  - DOMAIN-SUFFIX,adinfuse.com,AD-BAN
  - DOMAIN-SUFFIX,adirects.com,AD-BAN
  - DOMAIN-SUFFIX,adjust.io,AD-BAN
  - DOMAIN-SUFFIX,adkmob.com,AD-BAN
  - DOMAIN-SUFFIX,adlive.cn,AD-BAN
  - DOMAIN-SUFFIX,adlocus.com,AD-BAN
  - DOMAIN-SUFFIX,admaji.com,AD-BAN
  - DOMAIN-SUFFIX,admin6.com,AD-BAN
  - DOMAIN-SUFFIX,admon.cn,AD-BAN
  - DOMAIN-SUFFIX,adnyg.com,AD-BAN
  - DOMAIN-SUFFIX,adpolestar.net,AD-BAN
  - DOMAIN-SUFFIX,adpro.cn,AD-BAN
  - DOMAIN-SUFFIX,adpush.cn,AD-BAN
  - DOMAIN-SUFFIX,adquan.com,AD-BAN
  - DOMAIN-SUFFIX,adreal.cn,AD-BAN
  - DOMAIN-SUFFIX,ads8.com,AD-BAN
  - DOMAIN-SUFFIX,adsame.com,AD-BAN
  - DOMAIN-SUFFIX,adsmogo.com,AD-BAN
  - DOMAIN-SUFFIX,adsmogo.org,AD-BAN
  - DOMAIN-SUFFIX,adsunflower.com,AD-BAN
  - DOMAIN-SUFFIX,adsunion.com,AD-BAN
  - DOMAIN-SUFFIX,adtrk.me,AD-BAN
  - DOMAIN-SUFFIX,adups.com,AD-BAN
  - DOMAIN-SUFFIX,aduu.cn,AD-BAN
  - DOMAIN-SUFFIX,advertising.com,AD-BAN
  - DOMAIN-SUFFIX,adview.cn,AD-BAN
  - DOMAIN-SUFFIX,advmob.cn,AD-BAN
  - DOMAIN-SUFFIX,adwetec.com,AD-BAN
  - DOMAIN-SUFFIX,adwhirl.com,AD-BAN
  - DOMAIN-SUFFIX,adwo.com,AD-BAN
  - DOMAIN-SUFFIX,adxmi.com,AD-BAN
  - DOMAIN-SUFFIX,adyun.com,AD-BAN
  - DOMAIN-SUFFIX,adzerk.net,AD-BAN
  - DOMAIN-SUFFIX,agrant.cn,AD-BAN
  - DOMAIN-SUFFIX,agrantsem.com,AD-BAN
  - DOMAIN-SUFFIX,aihaoduo.cn,AD-BAN
  - DOMAIN-SUFFIX,ajapk.com,AD-BAN
  - DOMAIN-SUFFIX,allyes.cn,AD-BAN
  - DOMAIN-SUFFIX,allyes.com,AD-BAN
  - DOMAIN-SUFFIX,amazon-adsystem.com,AD-BAN
  - DOMAIN-SUFFIX,analysys.cn,AD-BAN
  - DOMAIN-SUFFIX,angsrvr.com,AD-BAN
  - DOMAIN-SUFFIX,anquan.org,AD-BAN
  - DOMAIN-SUFFIX,anysdk.com,AD-BAN
  - DOMAIN-SUFFIX,appadhoc.com,AD-BAN
  - DOMAIN-SUFFIX,appads.com,AD-BAN
  - DOMAIN-SUFFIX,appboy.com,AD-BAN
  - DOMAIN-SUFFIX,appdriver.cn,AD-BAN
  - DOMAIN-SUFFIX,appjiagu.com,AD-BAN
  - DOMAIN-SUFFIX,applifier.com,AD-BAN
  - DOMAIN-SUFFIX,appsflyer.com,AD-BAN
  - DOMAIN-SUFFIX,atdmt.com,AD-BAN
  - DOMAIN-SUFFIX,baifendian.com,AD-BAN
  - DOMAIN-SUFFIX,banmamedia.com,AD-BAN
  - DOMAIN-SUFFIX,baoyatu.cc,AD-BAN
  - DOMAIN-SUFFIX,baycode.cn,AD-BAN
  - DOMAIN-SUFFIX,bayimob.com,AD-BAN
  - DOMAIN-SUFFIX,behe.com,AD-BAN
  - DOMAIN-SUFFIX,bfshan.cn,AD-BAN
  - DOMAIN-SUFFIX,biddingos.com,AD-BAN
  - DOMAIN-SUFFIX,biddingx.com,AD-BAN
  - DOMAIN-SUFFIX,bjvvqu.cn,AD-BAN
  - DOMAIN-SUFFIX,bjxiaohua.com,AD-BAN
  - DOMAIN-SUFFIX,bloggerads.net,AD-BAN
  - DOMAIN-SUFFIX,branch.io,AD-BAN
  - DOMAIN-SUFFIX,bsdev.cn,AD-BAN
  - DOMAIN-SUFFIX,bshare.cn,AD-BAN
  - DOMAIN-SUFFIX,btyou.com,AD-BAN
  - DOMAIN-SUFFIX,bugtags.com,AD-BAN
  - DOMAIN-SUFFIX,buysellads.com,AD-BAN
  - DOMAIN-SUFFIX,c0563.com,AD-BAN
  - DOMAIN-SUFFIX,cacafly.com,AD-BAN
  - DOMAIN-SUFFIX,casee.cn,AD-BAN
  - DOMAIN-SUFFIX,cdnmaster.com,AD-BAN
  - DOMAIN-SUFFIX,chance-ad.com,AD-BAN
  - DOMAIN-SUFFIX,chanet.com.cn,AD-BAN
  - DOMAIN-SUFFIX,chartbeat.com,AD-BAN
  - DOMAIN-SUFFIX,chartboost.com,AD-BAN
  - DOMAIN-SUFFIX,chengadx.com,AD-BAN
  - DOMAIN-SUFFIX,chmae.com,AD-BAN
  - DOMAIN-SUFFIX,clickadu.com,AD-BAN
  - DOMAIN-SUFFIX,clicki.cn,AD-BAN
  - DOMAIN-SUFFIX,clicktracks.com,AD-BAN
  - DOMAIN-SUFFIX,clickzs.com,AD-BAN
  - DOMAIN-SUFFIX,cloudmobi.net,AD-BAN
  - DOMAIN-SUFFIX,cmcore.com,AD-BAN
  - DOMAIN-SUFFIX,cnxad.com,AD-BAN
  - DOMAIN-SUFFIX,cnzz.com,AD-BAN
  - DOMAIN-SUFFIX,cnzzlink.com,AD-BAN
  - DOMAIN-SUFFIX,cocounion.com,AD-BAN
  - DOMAIN-SUFFIX,coocaatv.com,AD-BAN
  - DOMAIN-SUFFIX,cooguo.com,AD-BAN
  - DOMAIN-SUFFIX,coolguang.com,AD-BAN
  - DOMAIN-SUFFIX,coremetrics.com,AD-BAN
  - DOMAIN-SUFFIX,cpmchina.co,AD-BAN
  - DOMAIN-SUFFIX,cpx24.com,AD-BAN
  - DOMAIN-SUFFIX,crasheye.cn,AD-BAN
  - DOMAIN-SUFFIX,crosschannel.com,AD-BAN
  - DOMAIN-SUFFIX,ctrmi.com,AD-BAN
  - DOMAIN-SUFFIX,customer-security.online,AD-BAN
  - DOMAIN-SUFFIX,daoyoudao.com,AD-BAN
  - DOMAIN-SUFFIX,datouniao.com,AD-BAN
  - DOMAIN-SUFFIX,ddapp.cn,AD-BAN
  - DOMAIN-SUFFIX,dianjoy.com,AD-BAN
  - DOMAIN-SUFFIX,dianru.com,AD-BAN
  - DOMAIN-SUFFIX,disqusads.com,AD-BAN
  - DOMAIN-SUFFIX,domob.cn,AD-BAN
  - DOMAIN-SUFFIX,domob.com.cn,AD-BAN
  - DOMAIN-SUFFIX,domob.org,AD-BAN
  - DOMAIN-SUFFIX,dotmore.com.tw,AD-BAN
  - DOMAIN-SUFFIX,doubleverify.com,AD-BAN
  - DOMAIN-SUFFIX,doudouguo.com,AD-BAN
  - DOMAIN-SUFFIX,doumob.com,AD-BAN
  - DOMAIN-SUFFIX,duanat.com,AD-BAN
  - DOMAIN-SUFFIX,duiba.com.cn,AD-BAN
  - DOMAIN-SUFFIX,duomeng.cn,AD-BAN
  - DOMAIN-SUFFIX,dxpmedia.com,AD-BAN
  - DOMAIN-SUFFIX,edigitalsurvey.com,AD-BAN
  - DOMAIN-SUFFIX,eduancm.com,AD-BAN
  - DOMAIN-SUFFIX,emarbox.com,AD-BAN
  - DOMAIN-SUFFIX,exosrv.com,AD-BAN
  - DOMAIN-SUFFIX,fancyapi.com,AD-BAN
  - DOMAIN-SUFFIX,feitian001.com,AD-BAN
  - DOMAIN-SUFFIX,feixin2.com,AD-BAN
  - DOMAIN-SUFFIX,flashtalking.com,AD-BAN
  - DOMAIN-SUFFIX,fraudmetrix.cn,AD-BAN
  - DOMAIN-SUFFIX,g1.tagtic.cn,AD-BAN
  - DOMAIN-SUFFIX,gentags.net,AD-BAN
  - DOMAIN-SUFFIX,gepush.com,AD-BAN
  - DOMAIN-SUFFIX,getui.com,AD-BAN
  - DOMAIN-SUFFIX,glispa.com,AD-BAN
  - DOMAIN-SUFFIX,go-mpulse,AD-BAN
  - DOMAIN-SUFFIX,go-mpulse.net,AD-BAN
  - DOMAIN-SUFFIX,godloveme.cn,AD-BAN
  - DOMAIN-SUFFIX,gridsum.com,AD-BAN
  - DOMAIN-SUFFIX,gridsumdissector.cn,AD-BAN
  - DOMAIN-SUFFIX,gridsumdissector.com,AD-BAN
  - DOMAIN-SUFFIX,growingio.com,AD-BAN
  - DOMAIN-SUFFIX,guohead.com,AD-BAN
  - DOMAIN-SUFFIX,guomob.com,AD-BAN
  - DOMAIN-SUFFIX,haoghost.com,AD-BAN
  - DOMAIN-SUFFIX,hivecn.cn,AD-BAN
  - DOMAIN-SUFFIX,hypers.com,AD-BAN
  - DOMAIN-SUFFIX,icast.cn,AD-BAN
  - DOMAIN-SUFFIX,igexin.com,AD-BAN
  - DOMAIN-SUFFIX,il8r.com,AD-BAN
  - DOMAIN-SUFFIX,imageter.com,AD-BAN
  - DOMAIN-SUFFIX,immob.cn,AD-BAN
  - DOMAIN-SUFFIX,inad.com,AD-BAN
  - DOMAIN-SUFFIX,inmobi.cn,AD-BAN
  - DOMAIN-SUFFIX,inmobi.net,AD-BAN
  - DOMAIN-SUFFIX,inmobicdn.cn,AD-BAN
  - DOMAIN-SUFFIX,inmobicdn.net,AD-BAN
  - DOMAIN-SUFFIX,innity.com,AD-BAN
  - DOMAIN-SUFFIX,instabug.com,AD-BAN
  - DOMAIN-SUFFIX,intely.cn,AD-BAN
  - DOMAIN-SUFFIX,iperceptions.com,AD-BAN
  - DOMAIN-SUFFIX,ipinyou.com,AD-BAN
  - DOMAIN-SUFFIX,irs01.com,AD-BAN
  - DOMAIN-SUFFIX,irs01.net,AD-BAN
  - DOMAIN-SUFFIX,irs09.com,AD-BAN
  - DOMAIN-SUFFIX,istreamsche.com,AD-BAN
  - DOMAIN-SUFFIX,jesgoo.com,AD-BAN
  - DOMAIN-SUFFIX,jiaeasy.net,AD-BAN
  - DOMAIN-SUFFIX,jiguang.cn,AD-BAN
  - DOMAIN-SUFFIX,jimdo.com,AD-BAN
  - DOMAIN-SUFFIX,jisucn.com,AD-BAN
  - DOMAIN-SUFFIX,jmgehn.cn,AD-BAN
  - DOMAIN-SUFFIX,jpush.cn,AD-BAN
  - DOMAIN-SUFFIX,jusha.com,AD-BAN
  - DOMAIN-SUFFIX,juzi.cn,AD-BAN
  - DOMAIN-SUFFIX,juzilm.com,AD-BAN
  - DOMAIN-SUFFIX,kejet.com,AD-BAN
  - DOMAIN-SUFFIX,kejet.net,AD-BAN
  - DOMAIN-SUFFIX,keydot.net,AD-BAN
  - DOMAIN-SUFFIX,keyrun.cn,AD-BAN
  - DOMAIN-SUFFIX,kmd365.com,AD-BAN
  - DOMAIN-SUFFIX,krux.net,AD-BAN
  - DOMAIN-SUFFIX,lnk0.com,AD-BAN
  - DOMAIN-SUFFIX,lnk8.cn,AD-BAN
  - DOMAIN-SUFFIX,localytics.com,AD-BAN
  - DOMAIN-SUFFIX,lomark.cn,AD-BAN
  - DOMAIN-SUFFIX,lotuseed.com,AD-BAN
  - DOMAIN-SUFFIX,lrswl.com,AD-BAN
  - DOMAIN-SUFFIX,lufax.com,AD-BAN
  - DOMAIN-SUFFIX,madhouse.cn,AD-BAN
  - DOMAIN-SUFFIX,madmini.com,AD-BAN
  - DOMAIN-SUFFIX,madserving.com,AD-BAN
  - DOMAIN-SUFFIX,magicwindow.cn,AD-BAN
  - DOMAIN-SUFFIX,mathtag.com,AD-BAN
  - DOMAIN-SUFFIX,maysunmedia.com,AD-BAN
  - DOMAIN-SUFFIX,mbai.cn,AD-BAN
  - DOMAIN-SUFFIX,mediaplex.com,AD-BAN
  - DOMAIN-SUFFIX,mediav.com,AD-BAN
  - DOMAIN-SUFFIX,megajoy.com,AD-BAN
  - DOMAIN-SUFFIX,mgogo.com,AD-BAN
  - DOMAIN-SUFFIX,miaozhen.com,AD-BAN
  - DOMAIN-SUFFIX,microad-cn.com,AD-BAN
  - DOMAIN-SUFFIX,miidi.net,AD-BAN
  - DOMAIN-SUFFIX,mijifen.com,AD-BAN
  - DOMAIN-SUFFIX,mixpanel.com,AD-BAN
  - DOMAIN-SUFFIX,mjmobi.com,AD-BAN
  - DOMAIN-SUFFIX,mng-ads.com,AD-BAN
  - DOMAIN-SUFFIX,moad.cn,AD-BAN
  - DOMAIN-SUFFIX,moatads.com,AD-BAN
  - DOMAIN-SUFFIX,mobaders.com,AD-BAN
  - DOMAIN-SUFFIX,mobclix.com,AD-BAN
  - DOMAIN-SUFFIX,mobgi.com,AD-BAN
  - DOMAIN-SUFFIX,mobisage.cn,AD-BAN
  - DOMAIN-SUFFIX,mobvista.com,AD-BAN
  - DOMAIN-SUFFIX,moogos.com,AD-BAN
  - DOMAIN-SUFFIX,mopub.com,AD-BAN
  - DOMAIN-SUFFIX,moquanad.com,AD-BAN
  - DOMAIN-SUFFIX,mpush.cn,AD-BAN
  - DOMAIN-SUFFIX,mxpnl.com,AD-BAN
  - DOMAIN-SUFFIX,myhug.cn,AD-BAN
  - DOMAIN-SUFFIX,mzy2014.com,AD-BAN
  - DOMAIN-SUFFIX,networkbench.com,AD-BAN
  - DOMAIN-SUFFIX,ninebox.cn,AD-BAN
  - DOMAIN-SUFFIX,ntalker.com,AD-BAN
  - DOMAIN-SUFFIX,nylalobghyhirgh.com,AD-BAN
  - DOMAIN-SUFFIX,o2omobi.com,AD-BAN
  - DOMAIN-SUFFIX,oadz.com,AD-BAN
  - DOMAIN-SUFFIX,oneapm.com,AD-BAN
  - DOMAIN-SUFFIX,onetad.com,AD-BAN
  - DOMAIN-SUFFIX,optaim.com,AD-BAN
  - DOMAIN-SUFFIX,optimix.asia,AD-BAN
  - DOMAIN-SUFFIX,optimix.cn,AD-BAN
  - DOMAIN-SUFFIX,optimizelyapis.com,AD-BAN
  - DOMAIN-SUFFIX,overture.com,AD-BAN
  - DOMAIN-SUFFIX,p0y.cn,AD-BAN
  - DOMAIN-SUFFIX,pagechoice.net,AD-BAN
  - DOMAIN-SUFFIX,pingdom.net,AD-BAN
  - DOMAIN-SUFFIX,plugrush.com,AD-BAN
  - DOMAIN-SUFFIX,popin.cc,AD-BAN
  - DOMAIN-SUFFIX,pro.cn,AD-BAN
  - DOMAIN-SUFFIX,publicidad.net,AD-BAN
  - DOMAIN-SUFFIX,publicidad.tv,AD-BAN
  - DOMAIN-SUFFIX,pubmatic.com,AD-BAN
  - DOMAIN-SUFFIX,pubnub.com,AD-BAN
  - DOMAIN-SUFFIX,qcl777.com,AD-BAN
  - DOMAIN-SUFFIX,qiyou.com,AD-BAN
  - DOMAIN-SUFFIX,qtmojo.com,AD-BAN
  - DOMAIN-SUFFIX,quantcount.com,AD-BAN
  - DOMAIN-SUFFIX,qucaigg.com,AD-BAN
  - DOMAIN-SUFFIX,qumi.com,AD-BAN
  - DOMAIN-SUFFIX,qxxys.com,AD-BAN
  - DOMAIN-SUFFIX,reachmax.cn,AD-BAN
  - DOMAIN-SUFFIX,responsys.net,AD-BAN
  - DOMAIN-SUFFIX,revsci.net,AD-BAN
  - DOMAIN-SUFFIX,rlcdn.com,AD-BAN
  - DOMAIN-SUFFIX,rtbasia.com,AD-BAN
  - DOMAIN-SUFFIX,sanya1.com,AD-BAN
  - DOMAIN-SUFFIX,scupio.com,AD-BAN
  - DOMAIN-SUFFIX,shuiguo.com,AD-BAN
  - DOMAIN-SUFFIX,shuzilm.cn,AD-BAN
  - DOMAIN-SUFFIX,similarweb.com,AD-BAN
  - DOMAIN-SUFFIX,sitemeter.com,AD-BAN
  - DOMAIN-SUFFIX,sitescout.com,AD-BAN
  - DOMAIN-SUFFIX,sitetag.us,AD-BAN
  - DOMAIN-SUFFIX,smartmad.com,AD-BAN
  - DOMAIN-SUFFIX,social-touch.com,AD-BAN
  - DOMAIN-SUFFIX,somecoding.com,AD-BAN
  - DOMAIN-SUFFIX,sponsorpay.com,AD-BAN
  - DOMAIN-SUFFIX,stargame.com,AD-BAN
  - DOMAIN-SUFFIX,stg8.com,AD-BAN
  - DOMAIN-SUFFIX,switchadhub.com,AD-BAN
  - DOMAIN-SUFFIX,sycbbs.com,AD-BAN
  - DOMAIN-SUFFIX,synacast.com,AD-BAN
  - DOMAIN-SUFFIX,sysdig.com,AD-BAN
  - DOMAIN-SUFFIX,talkingdata.com,AD-BAN
  - DOMAIN-SUFFIX,talkingdata.net,AD-BAN
  - DOMAIN-SUFFIX,tansuotv.com,AD-BAN
  - DOMAIN-SUFFIX,tanv.com,AD-BAN
  - DOMAIN-SUFFIX,tanx.com,AD-BAN
  - DOMAIN-SUFFIX,tapjoy.cn,AD-BAN
  - DOMAIN-SUFFIX,th7.cn,AD-BAN
  - DOMAIN-SUFFIX,thoughtleadr.com,AD-BAN
  - DOMAIN-SUFFIX,tianmidian.com,AD-BAN
  - DOMAIN-SUFFIX,tiqcdn.com,AD-BAN
  - DOMAIN-SUFFIX,touclick.com,AD-BAN
  - DOMAIN-SUFFIX,trafficjam.cn,AD-BAN
  - DOMAIN-SUFFIX,trafficmp.com,AD-BAN
  - DOMAIN-SUFFIX,tuia.cn,AD-BAN
  - DOMAIN-SUFFIX,ueadlian.com,AD-BAN
  - DOMAIN-SUFFIX,uerzyr.cn,AD-BAN
  - DOMAIN-SUFFIX,ugdtimg.com,AD-BAN
  - DOMAIN-SUFFIX,ugvip.com,AD-BAN
  - DOMAIN-SUFFIX,ujian.cc,AD-BAN
  - DOMAIN-SUFFIX,ukeiae.com,AD-BAN
  - DOMAIN-SUFFIX,umeng.co,AD-BAN
  - DOMAIN-SUFFIX,umeng.com,AD-BAN
  - DOMAIN-SUFFIX,umtrack.com,AD-BAN
  - DOMAIN-SUFFIX,unimhk.com,AD-BAN
  - DOMAIN-SUFFIX,union-wifi.com,AD-BAN
  - DOMAIN-SUFFIX,union001.com,AD-BAN
  - DOMAIN-SUFFIX,unionsy.com,AD-BAN
  - DOMAIN-SUFFIX,unlitui.com,AD-BAN
  - DOMAIN-SUFFIX,uri6.com,AD-BAN
  - DOMAIN-SUFFIX,ushaqi.com,AD-BAN
  - DOMAIN-SUFFIX,usingde.com,AD-BAN
  - DOMAIN-SUFFIX,uuzu.com,AD-BAN
  - DOMAIN-SUFFIX,uyunad.com,AD-BAN
  - DOMAIN-SUFFIX,vamaker.com,AD-BAN
  - DOMAIN-SUFFIX,vlion.cn,AD-BAN
  - DOMAIN-SUFFIX,voiceads.cn,AD-BAN
  - DOMAIN-SUFFIX,voiceads.com,AD-BAN
  - DOMAIN-SUFFIX,vpon.com,AD-BAN
  - DOMAIN-SUFFIX,vungle.cn,AD-BAN
  - DOMAIN-SUFFIX,vungle.com,AD-BAN
  - DOMAIN-SUFFIX,waps.cn,AD-BAN
  - DOMAIN-SUFFIX,wapx.cn,AD-BAN
  - DOMAIN-SUFFIX,webterren.com,AD-BAN
  - DOMAIN-SUFFIX,whpxy.com,AD-BAN
  - DOMAIN-SUFFIX,winads.cn,AD-BAN
  - DOMAIN-SUFFIX,winasdaq.com,AD-BAN
  - DOMAIN-SUFFIX,wiyun.com,AD-BAN
  - DOMAIN-SUFFIX,wooboo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,wqmobile.com,AD-BAN
  - DOMAIN-SUFFIX,wrating.com,AD-BAN
  - DOMAIN-SUFFIX,wumii.cn,AD-BAN
  - DOMAIN-SUFFIX,wwads.cn,AD-BAN
  - DOMAIN-SUFFIX,xcy8.com,AD-BAN
  - DOMAIN-SUFFIX,xdrig.com,AD-BAN
  - DOMAIN-SUFFIX,xiaozhen.com,AD-BAN
  - DOMAIN-SUFFIX,xibao100.com,AD-BAN
  - DOMAIN-SUFFIX,xtgreat.com,AD-BAN
  - DOMAIN-SUFFIX,xy.com,AD-BAN
  - DOMAIN-SUFFIX,yandui.com,AD-BAN
  - DOMAIN-SUFFIX,yigao.com,AD-BAN
  - DOMAIN-SUFFIX,yijifen.com,AD-BAN
  - DOMAIN-SUFFIX,yinooo.com,AD-BAN
  - DOMAIN-SUFFIX,yiqifa.com,AD-BAN
  - DOMAIN-SUFFIX,yiwk.com,AD-BAN
  - DOMAIN-SUFFIX,ylunion.com,AD-BAN
  - DOMAIN-SUFFIX,ymapp.com,AD-BAN
  - DOMAIN-SUFFIX,ymcdn.cn,AD-BAN
  - DOMAIN-SUFFIX,yongyuelm.com,AD-BAN
  - DOMAIN-SUFFIX,yooli.com,AD-BAN
  - DOMAIN-SUFFIX,youmi.net,AD-BAN
  - DOMAIN-SUFFIX,youxiaoad.com,AD-BAN
  - DOMAIN-SUFFIX,yoyi.com.cn,AD-BAN
  - DOMAIN-SUFFIX,yoyi.tv,AD-BAN
  - DOMAIN-SUFFIX,yrxmr.com,AD-BAN
  - DOMAIN-SUFFIX,ysjwj.com,AD-BAN
  - DOMAIN-SUFFIX,yunjiasu.com,AD-BAN
  - DOMAIN-SUFFIX,yunpifu.cn,AD-BAN
  - DOMAIN-SUFFIX,zampdsp.com,AD-BAN
  - DOMAIN-SUFFIX,zamplus.com,AD-BAN
  - DOMAIN-SUFFIX,zcdsp.com,AD-BAN
  - DOMAIN-SUFFIX,zhidian3g.cn,AD-BAN
  - DOMAIN-SUFFIX,zhiziyun.com,AD-BAN
  - DOMAIN-SUFFIX,zhjfad.com,AD-BAN
  - DOMAIN-SUFFIX,zqzxz.com,AD-BAN
  - DOMAIN-SUFFIX,zzsx8.com,AD-BAN
  - DOMAIN-SUFFIX,acuityplatform.com,AD-BAN
  - DOMAIN-SUFFIX,ad-stir.com,AD-BAN
  - DOMAIN-SUFFIX,ad-survey.com,AD-BAN
  - DOMAIN-SUFFIX,ad4game.com,AD-BAN
  - DOMAIN-SUFFIX,adcloud.jp,AD-BAN
  - DOMAIN-SUFFIX,adcolony.com,AD-BAN
  - DOMAIN-SUFFIX,addthis.com,AD-BAN
  - DOMAIN-SUFFIX,adfurikun.jp,AD-BAN
  - DOMAIN-SUFFIX,adhigh.net,AD-BAN
  - DOMAIN-SUFFIX,adhood.com,AD-BAN
  - DOMAIN-SUFFIX,adinall.com,AD-BAN
  - DOMAIN-SUFFIX,adition.com,AD-BAN
  - DOMAIN-SUFFIX,adk2x.com,AD-BAN
  - DOMAIN-SUFFIX,admarket.mobi,AD-BAN
  - DOMAIN-SUFFIX,admarvel.com,AD-BAN
  - DOMAIN-SUFFIX,admedia.com,AD-BAN
  - DOMAIN-SUFFIX,adnxs.com,AD-BAN
  - DOMAIN-SUFFIX,adotmob.com,AD-BAN
  - DOMAIN-SUFFIX,adperium.com,AD-BAN
  - DOMAIN-SUFFIX,adriver.ru,AD-BAN
  - DOMAIN-SUFFIX,adroll.com,AD-BAN
  - DOMAIN-SUFFIX,adsco.re,AD-BAN
  - DOMAIN-SUFFIX,adservice.com,AD-BAN
  - DOMAIN-SUFFIX,adsrvr.org,AD-BAN
  - DOMAIN-SUFFIX,adsymptotic.com,AD-BAN
  - DOMAIN-SUFFIX,adtaily.com,AD-BAN
  - DOMAIN-SUFFIX,adtech.de,AD-BAN
  - DOMAIN-SUFFIX,adtechjp.com,AD-BAN
  - DOMAIN-SUFFIX,adtechus.com,AD-BAN
  - DOMAIN-SUFFIX,airpush.com,AD-BAN
  - DOMAIN-SUFFIX,am15.net,AD-BAN
  - DOMAIN-SUFFIX,amobee.com,AD-BAN
  - DOMAIN-SUFFIX,appier.net,AD-BAN
  - DOMAIN-SUFFIX,applift.com,AD-BAN
  - DOMAIN-SUFFIX,apsalar.com,AD-BAN
  - DOMAIN-SUFFIX,atas.io,AD-BAN
  - DOMAIN-SUFFIX,awempire.com,AD-BAN
  - DOMAIN-SUFFIX,axonix.com,AD-BAN
  - DOMAIN-SUFFIX,beintoo.com,AD-BAN
  - DOMAIN-SUFFIX,bepolite.eu,AD-BAN
  - DOMAIN-SUFFIX,bidtheatre.com,AD-BAN
  - DOMAIN-SUFFIX,bidvertiser.com,AD-BAN
  - DOMAIN-SUFFIX,blismedia.com,AD-BAN
  - DOMAIN-SUFFIX,brucelead.com,AD-BAN
  - DOMAIN-SUFFIX,bttrack.com,AD-BAN
  - DOMAIN-SUFFIX,casalemedia.com,AD-BAN
  - DOMAIN-SUFFIX,celtra.com,AD-BAN
  - DOMAIN-SUFFIX,channeladvisor.com,AD-BAN
  - DOMAIN-SUFFIX,connexity.net,AD-BAN
  - DOMAIN-SUFFIX,criteo.com,AD-BAN
  - DOMAIN-SUFFIX,criteo.net,AD-BAN
  - DOMAIN-SUFFIX,csbew.com,AD-BAN
  - DOMAIN-SUFFIX,directrev.com,AD-BAN
  - DOMAIN-SUFFIX,dumedia.ru,AD-BAN
  - DOMAIN-SUFFIX,effectivemeasure.com,AD-BAN
  - DOMAIN-SUFFIX,effectivemeasure.net,AD-BAN
  - DOMAIN-SUFFIX,eqads.com,AD-BAN
  - DOMAIN-SUFFIX,everesttech.net,AD-BAN
  - DOMAIN-SUFFIX,exoclick.com,AD-BAN
  - DOMAIN-SUFFIX,extend.tv,AD-BAN
  - DOMAIN-SUFFIX,eyereturn.com,AD-BAN
  - DOMAIN-SUFFIX,fastapi.net,AD-BAN
  - DOMAIN-SUFFIX,fastclick.com,AD-BAN
  - DOMAIN-SUFFIX,fastclick.net,AD-BAN
  - DOMAIN-SUFFIX,flurry.com,AD-BAN
  - DOMAIN-SUFFIX,gosquared.com,AD-BAN
  - DOMAIN-SUFFIX,gtags.net,AD-BAN
  - DOMAIN-SUFFIX,heyzap.com,AD-BAN
  - DOMAIN-SUFFIX,histats.com,AD-BAN
  - DOMAIN-SUFFIX,hitslink.com,AD-BAN
  - DOMAIN-SUFFIX,hot-mob.com,AD-BAN
  - DOMAIN-SUFFIX,hyperpromote.com,AD-BAN
  - DOMAIN-SUFFIX,i-mobile.co.jp,AD-BAN
  - DOMAIN-SUFFIX,imrworldwide.com,AD-BAN
  - DOMAIN-SUFFIX,inmobi.com,AD-BAN
  - DOMAIN-SUFFIX,inner-active.mobi,AD-BAN
  - DOMAIN-SUFFIX,intentiq.com,AD-BAN
  - DOMAIN-SUFFIX,inter1ads.com,AD-BAN
  - DOMAIN-SUFFIX,ipredictive.com,AD-BAN
  - DOMAIN-SUFFIX,ironsrc.com,AD-BAN
  - DOMAIN-SUFFIX,iskyworker.com,AD-BAN
  - DOMAIN-SUFFIX,jizzads.com,AD-BAN
  - DOMAIN-SUFFIX,juicyads.com,AD-BAN
  - DOMAIN-SUFFIX,kochava.com,AD-BAN
  - DOMAIN-SUFFIX,leadbolt.com,AD-BAN
  - DOMAIN-SUFFIX,leadbolt.net,AD-BAN
  - DOMAIN-SUFFIX,leadboltads.net,AD-BAN
  - DOMAIN-SUFFIX,leadboltapps.net,AD-BAN
  - DOMAIN-SUFFIX,leadboltmobile.net,AD-BAN
  - DOMAIN-SUFFIX,lenzmx.com,AD-BAN
  - DOMAIN-SUFFIX,liveadvert.com,AD-BAN
  - DOMAIN-SUFFIX,marketgid.com,AD-BAN
  - DOMAIN-SUFFIX,marketo.com,AD-BAN
  - DOMAIN-SUFFIX,mdotm.com,AD-BAN
  - DOMAIN-SUFFIX,medialytics.com,AD-BAN
  - DOMAIN-SUFFIX,medialytics.io,AD-BAN
  - DOMAIN-SUFFIX,meetrics.com,AD-BAN
  - DOMAIN-SUFFIX,meetrics.net,AD-BAN
  - DOMAIN-SUFFIX,mgid.com,AD-BAN
  - DOMAIN-SUFFIX,millennialmedia.com,AD-BAN
  - DOMAIN-SUFFIX,mobadme.jp,AD-BAN
  - DOMAIN-SUFFIX,mobfox.com,AD-BAN
  - DOMAIN-SUFFIX,mobileadtrading.com,AD-BAN
  - DOMAIN-SUFFIX,mobilityware.com,AD-BAN
  - DOMAIN-SUFFIX,mojiva.com,AD-BAN
  - DOMAIN-SUFFIX,mookie1.com,AD-BAN
  - DOMAIN-SUFFIX,msads.net,AD-BAN
  - DOMAIN-SUFFIX,mydas.mobi,AD-BAN
  - DOMAIN-SUFFIX,nend.net,AD-BAN
  - DOMAIN-SUFFIX,netshelter.net,AD-BAN
  - DOMAIN-SUFFIX,nexage.com,AD-BAN
  - DOMAIN-SUFFIX,owneriq.net,AD-BAN
  - DOMAIN-SUFFIX,pixels.asia,AD-BAN
  - DOMAIN-SUFFIX,plista.com,AD-BAN
  - DOMAIN-SUFFIX,popads.net,AD-BAN
  - DOMAIN-SUFFIX,powerlinks.com,AD-BAN
  - DOMAIN-SUFFIX,propellerads.com,AD-BAN
  - DOMAIN-SUFFIX,quantserve.com,AD-BAN
  - DOMAIN-SUFFIX,rayjump.com,AD-BAN
  - DOMAIN-SUFFIX,revdepo.com,AD-BAN
  - DOMAIN-SUFFIX,rubiconproject.com,AD-BAN
  - DOMAIN-SUFFIX,sape.ru,AD-BAN
  - DOMAIN-SUFFIX,scorecardresearch.com,AD-BAN
  - DOMAIN-SUFFIX,segment.com,AD-BAN
  - DOMAIN-SUFFIX,serving-sys.com,AD-BAN
  - DOMAIN-SUFFIX,sharethis.com,AD-BAN
  - DOMAIN-SUFFIX,smaato.com,AD-BAN
  - DOMAIN-SUFFIX,smaato.net,AD-BAN
  - DOMAIN-SUFFIX,smartadserver.com,AD-BAN
  - DOMAIN-SUFFIX,smartnews-ads.com,AD-BAN
  - DOMAIN-SUFFIX,startapp.com,AD-BAN
  - DOMAIN-SUFFIX,startappexchange.com,AD-BAN
  - DOMAIN-SUFFIX,statcounter.com,AD-BAN
  - DOMAIN-SUFFIX,steelhousemedia.com,AD-BAN
  - DOMAIN-SUFFIX,stickyadstv.com,AD-BAN
  - DOMAIN-SUFFIX,supersonic.com,AD-BAN
  - DOMAIN-SUFFIX,taboola.com,AD-BAN
  - DOMAIN-SUFFIX,tapjoy.com,AD-BAN
  - DOMAIN-SUFFIX,tapjoyads.com,AD-BAN
  - DOMAIN-SUFFIX,trafficjunky.com,AD-BAN
  - DOMAIN-SUFFIX,trafficjunky.net,AD-BAN
  - DOMAIN-SUFFIX,tribalfusion.com,AD-BAN
  - DOMAIN-SUFFIX,turn.com,AD-BAN
  - DOMAIN-SUFFIX,uberads.com,AD-BAN
  - DOMAIN-SUFFIX,vidoomy.com,AD-BAN
  - DOMAIN-SUFFIX,viglink.com,AD-BAN
  - DOMAIN-SUFFIX,voicefive.com,AD-BAN
  - DOMAIN-SUFFIX,wedolook.com,AD-BAN
  - DOMAIN-SUFFIX,yadro.ru,AD-BAN
  - DOMAIN-SUFFIX,yengo.com,AD-BAN
  - DOMAIN-SUFFIX,zedo.com,AD-BAN
  - DOMAIN-SUFFIX,zemanta.com,AD-BAN
  - DOMAIN-SUFFIX,11h5.com,AD-BAN
  - DOMAIN-SUFFIX,1kxun.mobi,AD-BAN
  - DOMAIN-SUFFIX,26zsd.cn,AD-BAN
  - DOMAIN-SUFFIX,519397.com,AD-BAN
  - DOMAIN-SUFFIX,626uc.com,AD-BAN
  - DOMAIN-SUFFIX,915.com,AD-BAN
  - DOMAIN-SUFFIX,appget.cn,AD-BAN
  - DOMAIN-SUFFIX,appuu.cn,AD-BAN
  - DOMAIN-SUFFIX,coinhive.com,AD-BAN
  - DOMAIN-SUFFIX,huodonghezi.cn,AD-BAN
  - DOMAIN-SUFFIX,vcbn65.xyz,AD-BAN
  - DOMAIN-SUFFIX,wanfeng1.com,AD-BAN
  - DOMAIN-SUFFIX,wep016.top,AD-BAN
  - DOMAIN-SUFFIX,win-stock.com.cn,AD-BAN
  - DOMAIN-SUFFIX,zantainet.com,AD-BAN
  - DOMAIN-SUFFIX,dh54wf.xyz,AD-BAN
  - DOMAIN-SUFFIX,g2q3e.cn,AD-BAN
  - DOMAIN-SUFFIX,114so.cn,AD-BAN
  - DOMAIN-SUFFIX,go.10086.cn,AD-BAN
  - DOMAIN-SUFFIX,hivedata.cc,AD-BAN
  - DOMAIN-SUFFIX,navi.gd.chinamobile.com,AD-BAN
  - DOMAIN-SUFFIX,a.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,adgeo.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.126.net,AD-BAN
  - DOMAIN-SUFFIX,bobo.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,c.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,clkservice.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,conv.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,dsp-impr2.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,dsp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,fa.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,g.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,g1.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,gb.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,gorgon.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,haitaoad.nosdn.127.net,AD-BAN
  - DOMAIN-SUFFIX,iadmatvideo.nosdn.127.net,AD-BAN
  - DOMAIN-SUFFIX,img1.126.net,AD-BAN
  - DOMAIN-SUFFIX,img2.126.net,AD-BAN
  - DOMAIN-SUFFIX,ir.mail.126.com,AD-BAN
  - DOMAIN-SUFFIX,ir.mail.yeah.net,AD-BAN
  - DOMAIN-SUFFIX,mimg.126.net,AD-BAN
  - DOMAIN-SUFFIX,nc004x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,nc045x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,nex.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,oimagea2.ydstatic.com,AD-BAN
  - DOMAIN-SUFFIX,pagechoice.net,AD-BAN
  - DOMAIN-SUFFIX,prom.gome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,qchannel0d.cn,AD-BAN
  - DOMAIN-SUFFIX,qt002x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,rlogs.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,static.flv.uuzuonline.com,AD-BAN
  - DOMAIN-SUFFIX,tb060x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,tb104x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,union.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,wanproxy.127.net,AD-BAN
  - DOMAIN-SUFFIX,ydpushserver.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,cvda.17173.com,AD-BAN
  - DOMAIN-SUFFIX,imgapp.yeyou.com,AD-BAN
  - DOMAIN-SUFFIX,log1.17173.com,AD-BAN
  - DOMAIN-SUFFIX,s.17173cdn.com,AD-BAN
  - DOMAIN-SUFFIX,ue.yeyoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,vda.17173.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.wanmei.com,AD-BAN
  - DOMAIN-SUFFIX,gg.stargame.com,AD-BAN
  - DOMAIN-SUFFIX,dl.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,download.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,houtai.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,jifen.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,jifendownload.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,minipage.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,wan.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,zhushou.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,3600.com,AD-BAN
  - DOMAIN-SUFFIX,gamebox.360.cn,AD-BAN
  - DOMAIN-SUFFIX,jiagu.360.cn,AD-BAN
  - DOMAIN-SUFFIX,kuaikan.netmon.360safe.com,AD-BAN
  - DOMAIN-SUFFIX,leak.360.cn,AD-BAN
  - DOMAIN-SUFFIX,lianmeng.360.cn,AD-BAN
  - DOMAIN-SUFFIX,pub.se.360.cn,AD-BAN
  - DOMAIN-SUFFIX,s.so.360.cn,AD-BAN
  - DOMAIN-SUFFIX,shouji.360.cn,AD-BAN
  - DOMAIN-SUFFIX,soft.data.weather.360.cn,AD-BAN
  - DOMAIN-SUFFIX,stat.360safe.com,AD-BAN
  - DOMAIN-SUFFIX,stat.m.360.cn,AD-BAN
  - DOMAIN-SUFFIX,update.360safe.com,AD-BAN
  - DOMAIN-SUFFIX,wan.360.cn,AD-BAN
  - DOMAIN-SUFFIX,58.xgo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,brandshow.58.com,AD-BAN
  - DOMAIN-SUFFIX,imp.xgo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,jing.58.com,AD-BAN
  - DOMAIN-SUFFIX,stat.xgo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,track.58.com,AD-BAN
  - DOMAIN-SUFFIX,tracklog.58.com,AD-BAN
  - DOMAIN-SUFFIX,acjs.aliyun.com,AD-BAN
  - DOMAIN-SUFFIX,adash-c.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,adash-c.ut.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,adashx4yt.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,adashxgc.ut.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,afp.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,ai.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,alipaylog.com,AD-BAN
  - DOMAIN-SUFFIX,atanx.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,atanx2.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,fav.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,g.click.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,g.tbcdn.cn,AD-BAN
  - DOMAIN-SUFFIX,gma.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,gtmsdd.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,hydra.alibaba.com,AD-BAN
  - DOMAIN-SUFFIX,m.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,pindao.huoban.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,re.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,redirect.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,rj.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,sdkinit.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,show.re.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,simaba.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,simaba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,srd.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,strip.taobaocdn.com,AD-BAN
  - DOMAIN-SUFFIX,tns.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,tyh.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,userimg.qunar.com,AD-BAN
  - DOMAIN-SUFFIX,yiliao.hupan.com,AD-BAN
  - DOMAIN-SUFFIX,3dns-2.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,3dns-3.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,activate-sea.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,activate-sjc0.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,activate.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,adobe-dns-2.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,adobe-dns-3.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,adobe-dns.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,ereg.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,geo2.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,hl2rcv.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,hlrcv.stage.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,lm.licenses.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,lmlicenses.wip4.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,na1r.services.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,na2m-pr.licenses.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,practivate.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,wip3.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,wwis-dubc1-vip60.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,adserver.unityads.unity3d.com,AD-BAN
  - DOMAIN-SUFFIX,33.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,adproxy.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,al.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,alert.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,applogapi.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,c.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,cmx.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,dspmnt.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,pcd.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,push.app.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,pvx.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,rd.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,rdx.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,stats.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,a.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,a.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ad.duapps.com,AD-BAN
  - DOMAIN-SUFFIX,ad.player.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,adm.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,adm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,adscdn.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,adscdn.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,adx.xiaodutv.com,AD-BAN
  - DOMAIN-SUFFIX,ae.bdstatic.com,AD-BAN
  - DOMAIN-SUFFIX,afd.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,afd.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,als.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,als.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,anquan.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,anquan.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,antivirus.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,api.mobula.sdk.duapps.com,AD-BAN
  - DOMAIN-SUFFIX,appc.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,appc.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,as.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,as.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,baichuan.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,baidu9635.com,AD-BAN
  - DOMAIN-SUFFIX,baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,baidutv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,banlv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,bar.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,bdplus.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,btlaunch.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,c.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,c.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cb.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cb.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cbjs.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cbjs.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cbjslog.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cbjslog.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cjhq.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cjhq.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cleaner.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,click.bes.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,click.hm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,click.qianqian.com,AD-BAN
  - DOMAIN-SUFFIX,cm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpro.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cpro.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpro.baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,cpro.tieba.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpro.zhidao.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpro2.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cpro2.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpu-admin.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,crs.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,crs.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,datax.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl-vip.bav.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl-vip.pcfaster.baidu.co.th,AD-BAN
  - DOMAIN-SUFFIX,dl.client.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl.ops.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl1sw.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl2.bav.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dlsw.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dlsw.br.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,download.bav.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,download.sd.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,drmcmm.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,drmcmm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dup.baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,dxp.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dzl.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,e.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,e.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,eclick.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,eclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ecma.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,ecmb.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,ecmc.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,eiv.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,eiv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,em.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ers.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,f10.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,fc-.cdn.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,fc-feed.cdn.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,fclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,fexclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,g.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,gimg.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,guanjia.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,hc.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,hc.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,hm.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,hm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,hmma.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,hmma.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,hpd.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,hpd.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,idm-su.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,iebar.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ikcode.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,imageplus.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,imageplus.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,img.taotaosou.cn,AD-BAN
  - DOMAIN-SUFFIX,img01.taotaosou.cn,AD-BAN
  - DOMAIN-SUFFIX,itsdata.map.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,j.br.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,kstj.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,log.music.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,log.nuomi.com,AD-BAN
  - DOMAIN-SUFFIX,m1.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ma.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,ma.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,mg09.zhaopin.com,AD-BAN
  - DOMAIN-SUFFIX,mipcache.bdstatic.com,AD-BAN
  - DOMAIN-SUFFIX,mobads-logs.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,mobads-logs.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,mobads.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,mobads.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,mpro.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,mtj.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,mtj.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,neirong.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,nsclick.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,nsclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,nsclickvideo.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,openrcv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,pc.videoclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,pos.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,pups.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,pups.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,pups.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,push.music.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,push.zhanzhang.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,qchannel0d.cn,AD-BAN
  - DOMAIN-SUFFIX,qianclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,release.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,res.limei.com,AD-BAN
  - DOMAIN-SUFFIX,res.mi.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,rigel.baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,river.zhidao.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,rj.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,rj.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,rp.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,rp.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,rplog.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,s.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,sclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,sestat.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,shadu.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,share.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,sobar.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,sobartop.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,spcode.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,spcode.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,stat.v.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,su.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,su.bdstatic.com,AD-BAN
  - DOMAIN-SUFFIX,tk.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,tk.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tkweb.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tob-cms.bj.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,toolbar.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tracker.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tuijian.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tuisong.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,tuisong.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ubmcmm.baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,ucstat.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,ucstat.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ulic.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ulog.imap.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,union.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,union.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,unionimage.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,utility.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,utility.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,utk.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,utk.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,videopush.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,videopush.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,vv84.bj.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,w.gdown.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,w.x.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,wangmeng.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,wangmeng.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,weishi.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,wenku-cms.bj.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,wisepush.video.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,wm.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,wm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,znsv.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,znsv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,zz.bdstatic.com,AD-BAN
  - DOMAIN-SUFFIX,zzy1.quyaoya.com,AD-BAN
  - DOMAIN-SUFFIX,ad.zhangyue.com,AD-BAN
  - DOMAIN-SUFFIX,adm.ps.easou.com,AD-BAN
  - DOMAIN-SUFFIX,aishowbger.com,AD-BAN
  - DOMAIN-SUFFIX,api.itaoxiaoshuo.com,AD-BAN
  - DOMAIN-SUFFIX,assets.ps.easou.com,AD-BAN
  - DOMAIN-SUFFIX,bbcoe.cn,AD-BAN
  - DOMAIN-SUFFIX,cj.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,dkeyn.com,AD-BAN
  - DOMAIN-SUFFIX,drdwy.com,AD-BAN
  - DOMAIN-SUFFIX,e.aa985.cn,AD-BAN
  - DOMAIN-SUFFIX,e.v02u9.cn,AD-BAN
  - DOMAIN-SUFFIX,e701.net,AD-BAN
  - DOMAIN-SUFFIX,ehxyz.com,AD-BAN
  - DOMAIN-SUFFIX,ethod.gzgmjcx.com,AD-BAN
  - DOMAIN-SUFFIX,focuscat.com,AD-BAN
  - DOMAIN-SUFFIX,game.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,hdswgc.com,AD-BAN
  - DOMAIN-SUFFIX,jyd.fjzdmy.com,AD-BAN
  - DOMAIN-SUFFIX,m.ourlj.com,AD-BAN
  - DOMAIN-SUFFIX,m.txtxr.com,AD-BAN
  - DOMAIN-SUFFIX,m.vsxet.com,AD-BAN
  - DOMAIN-SUFFIX,miam4.cn,AD-BAN
  - DOMAIN-SUFFIX,o.if.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,p.vq6nsu.cn,AD-BAN
  - DOMAIN-SUFFIX,picture.duokan.com,AD-BAN
  - DOMAIN-SUFFIX,push.zhangyue.com,AD-BAN
  - DOMAIN-SUFFIX,pyerc.com,AD-BAN
  - DOMAIN-SUFFIX,s1.cmfu.com,AD-BAN
  - DOMAIN-SUFFIX,sc.shayugg.com,AD-BAN
  - DOMAIN-SUFFIX,sdk.cferw.com,AD-BAN
  - DOMAIN-SUFFIX,sezvc.com,AD-BAN
  - DOMAIN-SUFFIX,sys.zhangyue.com,AD-BAN
  - DOMAIN-SUFFIX,tjlog.ps.easou.com,AD-BAN
  - DOMAIN-SUFFIX,tongji.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,ut2.shuqistat.com,AD-BAN
  - DOMAIN-SUFFIX,xgcsr.com,AD-BAN
  - DOMAIN-SUFFIX,xjq.jxmqkj.com,AD-BAN
  - DOMAIN-SUFFIX,xpe.cxaerp.com,AD-BAN
  - DOMAIN-SUFFIX,xtzxmy.com,AD-BAN
  - DOMAIN-SUFFIX,xyrkl.com,AD-BAN
  - DOMAIN-SUFFIX,zhuanfakong.com,AD-BAN
  - DOMAIN-SUFFIX,ad.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,dsp.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,ic.snssdk.com,AD-BAN
  - DOMAIN-SUFFIX,log.snssdk.com,AD-BAN
  - DOMAIN-SUFFIX,nativeapp.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,pangolin-sdk-toutiao-b.com,AD-BAN
  - DOMAIN-SUFFIX,pangolin-sdk-toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,pangolin.snssdk.com,AD-BAN
  - DOMAIN-SUFFIX,partner.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,pglstatp-toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,sm.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,a.dangdang.com,AD-BAN
  - DOMAIN-SUFFIX,click.dangdang.com,AD-BAN
  - DOMAIN-SUFFIX,schprompt.dangdang.com,AD-BAN
  - DOMAIN-SUFFIX,t.dangdang.com,AD-BAN
  - DOMAIN-SUFFIX,ad.duomi.com,AD-BAN
  - DOMAIN-SUFFIX,boxshows.com,AD-BAN
  - DOMAIN-SUFFIX,staticxx.facebook.com,AD-BAN
  - DOMAIN-SUFFIX,click1n.soufun.com,AD-BAN
  - DOMAIN-SUFFIX,clickm.fang.com,AD-BAN
  - DOMAIN-SUFFIX,clickn.fang.com,AD-BAN
  - DOMAIN-SUFFIX,countpvn.light.fang.com,AD-BAN
  - DOMAIN-SUFFIX,countubn.light.soufun.com,AD-BAN
  - DOMAIN-SUFFIX,mshow.fang.com,AD-BAN
  - DOMAIN-SUFFIX,tongji.home.soufun.com,AD-BAN
  - DOMAIN-SUFFIX,admob.com,AD-BAN
  - DOMAIN-SUFFIX,ads.gmodules.com,AD-BAN
  - DOMAIN-SUFFIX,ads.google.com,AD-BAN
  - DOMAIN-SUFFIX,adservice.google.com,AD-BAN
  - DOMAIN-SUFFIX,afd.l.google.com,AD-BAN
  - DOMAIN-SUFFIX,badad.googleplex.com,AD-BAN
  - DOMAIN-SUFFIX,csi.gstatic.com,AD-BAN
  - DOMAIN-SUFFIX,doubleclick.com,AD-BAN
  - DOMAIN-SUFFIX,doubleclick.net,AD-BAN
  - DOMAIN-SUFFIX,google-analytics.com,AD-BAN
  - DOMAIN-SUFFIX,googleadservices.com,AD-BAN
  - DOMAIN-SUFFIX,googleadsserving.cn,AD-BAN
  - DOMAIN-SUFFIX,googlecommerce.com,AD-BAN
  - DOMAIN-SUFFIX,googlesyndication.com,AD-BAN
  - DOMAIN-SUFFIX,mobileads.google.com,AD-BAN
  - DOMAIN-SUFFIX,pagead-tpc.l.google.com,AD-BAN
  - DOMAIN-SUFFIX,pagead.google.com,AD-BAN
  - DOMAIN-SUFFIX,pagead.l.google.com,AD-BAN
  - DOMAIN-SUFFIX,service.urchin.com,AD-BAN
  - DOMAIN-SUFFIX,ads.union.jd.com,AD-BAN
  - DOMAIN-SUFFIX,c-nfa.jd.com,AD-BAN
  - DOMAIN-SUFFIX,cps.360buy.com,AD-BAN
  - DOMAIN-SUFFIX,img-x.jd.com,AD-BAN
  - DOMAIN-SUFFIX,jrclick.jd.com,AD-BAN
  - DOMAIN-SUFFIX,jzt.jd.com,AD-BAN
  - DOMAIN-SUFFIX,policy.jd.com,AD-BAN
  - DOMAIN-SUFFIX,stat.m.jd.com,AD-BAN
  - DOMAIN-SUFFIX,ads.service.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,adsfile.bssdlbig.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,d.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,downmobile.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,gad.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,game.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,gamebox.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,gcapi.sy.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,gg.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,install.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,install2.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,kgmobilestat.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,kuaikaiapp.com,AD-BAN
  - DOMAIN-SUFFIX,log.stat.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,log.web.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,minidcsc.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,mo.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,mobilelog.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,msg.mobile.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,mvads.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,p.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,push.mobile.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,rtmonitor.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,sdn.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,tj.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,update.mobile.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,apk.shouji.koowo.com,AD-BAN
  - DOMAIN-SUFFIX,deliver.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,g.koowo.com,AD-BAN
  - DOMAIN-SUFFIX,g.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,kwmsg.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,log.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,mobilead.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,msclick2.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,msphoneclick.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,updatepage.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,wa.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,webstat.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,aider-res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,api-flow.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,api-game.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,api-push.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,aries.mzres.com,AD-BAN
  - DOMAIN-SUFFIX,bro.flyme.cn,AD-BAN
  - DOMAIN-SUFFIX,cal.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,ebook.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,ebook.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,game-res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,game.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,infocenter.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,openapi-news.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,push.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,reader.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,reader.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,t-e.flyme.cn,AD-BAN
  - DOMAIN-SUFFIX,t-flow.flyme.cn,AD-BAN
  - DOMAIN-SUFFIX,tongji-res1.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,tongji.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,umid.orion.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,upush.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,uxip.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,a.koudai.com,AD-BAN
  - DOMAIN-SUFFIX,adui.tg.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,corp.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,dc.meitustat.com,AD-BAN
  - DOMAIN-SUFFIX,gg.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,mdc.meitustat.com,AD-BAN
  - DOMAIN-SUFFIX,meitubeauty.meitudata.com,AD-BAN
  - DOMAIN-SUFFIX,message.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,rabbit.meitustat.com,AD-BAN
  - DOMAIN-SUFFIX,rabbit.tg.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,tuiguang.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,xiuxiu.android.dl.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,xiuxiu.mobile.meitudata.com,AD-BAN
  - DOMAIN-SUFFIX,a.market.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,ad.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,ad1.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,adv.sec.intl.miui.com,AD-BAN
  - DOMAIN-SUFFIX,adv.sec.miui.com,AD-BAN
  - DOMAIN-SUFFIX,bss.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,d.g.mi.com,AD-BAN
  - DOMAIN-SUFFIX,data.mistat.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,de.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,dvb.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,jellyfish.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,migc.g.mi.com,AD-BAN
  - DOMAIN-SUFFIX,migcreport.g.mi.com,AD-BAN
  - DOMAIN-SUFFIX,notice.game.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,ppurifier.game.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,r.browser.miui.com,AD-BAN
  - DOMAIN-SUFFIX,security.browser.miui.com,AD-BAN
  - DOMAIN-SUFFIX,shenghuo.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,stat.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,union.mi.com,AD-BAN
  - DOMAIN-SUFFIX,wtradv.market.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,ad.api.moji.com,AD-BAN
  - DOMAIN-SUFFIX,app.moji001.com,AD-BAN
  - DOMAIN-SUFFIX,cdn.moji002.com,AD-BAN
  - DOMAIN-SUFFIX,cdn2.moji002.com,AD-BAN
  - DOMAIN-SUFFIX,fds.api.moji.com,AD-BAN
  - DOMAIN-SUFFIX,log.moji.com,AD-BAN
  - DOMAIN-SUFFIX,stat.moji.com,AD-BAN
  - DOMAIN-SUFFIX,ugc.moji001.com,AD-BAN
  - DOMAIN-SUFFIX,ad.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,admgr.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,dload.qd.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,logger.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,s.qd.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,s.qd.qingtingfm.com,AD-BAN
  - DOMAIN-KEYWORD,omgmtaw,AD-BAN
  - DOMAIN,adsmind.apdcdn.tc.qq.com,AD-BAN
  - DOMAIN,adsmind.gdtimg.com,AD-BAN
  - DOMAIN,adsmind.tc.qq.com,AD-BAN
  - DOMAIN,pgdt.gtimg.cn,AD-BAN
  - DOMAIN,pgdt.gtimg.com,AD-BAN
  - DOMAIN,pgdt.ugdtimg.com,AD-BAN
  - DOMAIN,splashqqlive.gtimg.com,AD-BAN
  - DOMAIN,wa.gtimg.com,AD-BAN
  - DOMAIN,wxsnsdy.wxs.qq.com,AD-BAN
  - DOMAIN,wxsnsdythumb.wxs.qq.com,AD-BAN
  - DOMAIN-SUFFIX,act.qq.com,AD-BAN
  - DOMAIN-SUFFIX,ad.qun.qq.com,AD-BAN
  - DOMAIN-SUFFIX,adsfile.qq.com,AD-BAN
  - DOMAIN-SUFFIX,bugly.qq.com,AD-BAN
  - DOMAIN-SUFFIX,buluo.qq.com,AD-BAN
  - DOMAIN-SUFFIX,e.qq.com,AD-BAN
  - DOMAIN-SUFFIX,gdt.qq.com,AD-BAN
  - DOMAIN-SUFFIX,l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,monitor.qq.com,AD-BAN
  - DOMAIN-SUFFIX,pingma.qq.com,AD-BAN
  - DOMAIN-SUFFIX,pingtcss.qq.com,AD-BAN
  - DOMAIN-SUFFIX,report.qq.com,AD-BAN
  - DOMAIN-SUFFIX,tajs.qq.com,AD-BAN
  - DOMAIN-SUFFIX,tcss.qq.com,AD-BAN
  - DOMAIN-SUFFIX,uu.qq.com,AD-BAN
  - DOMAIN-SUFFIX,ebp.renren.com,AD-BAN
  - DOMAIN-SUFFIX,jebe.renren.com,AD-BAN
  - DOMAIN-SUFFIX,jebe.xnimg.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,adbox.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,add.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,adimg.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,adm.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,alitui.weibo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,biz.weibo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,cre.dp.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,dcads.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,dd.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,dmp.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,game.weibo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,gw5.push.mcp.weibo.cn,AD-BAN
  - DOMAIN-SUFFIX,leju.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,log.mix.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,mobileads.dx.cn,AD-BAN
  - DOMAIN-SUFFIX,newspush.sinajs.cn,AD-BAN
  - DOMAIN-SUFFIX,pay.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,sax.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,sax.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,saxd.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,sdkapp.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,sdkapp.uve.weibo.com,AD-BAN
  - DOMAIN-SUFFIX,sdkclick.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,slog.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,trends.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,tui.weibo.com,AD-BAN
  - DOMAIN-SUFFIX,u1.img.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,wax.weibo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,wbapp.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,wbapp.uve.weibo.com,AD-BAN
  - DOMAIN-SUFFIX,wbclick.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,wbpctips.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,zymo.mps.weibo.com,AD-BAN
  - DOMAIN-SUFFIX,123.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,123.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,adsence.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,amfi.gou.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,brand.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,cpc.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,epro.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,fair.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,files2.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,galaxy.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,golden1.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,goto.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,inte.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,iwan.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,lu.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,lu.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,pb.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,pd.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,pv.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,theta.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,wan.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,wangmeng.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,applovin.com,AD-BAN
  - DOMAIN-SUFFIX,guangzhuiyuan.com,AD-BAN
  - DOMAIN-SUFFIX,ads-twitter.com,AD-BAN
  - DOMAIN-SUFFIX,ads.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,p.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,scribe.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,syndication-o.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,syndication.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,tellapart.com,AD-BAN
  - DOMAIN-SUFFIX,urls.api.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,adslot.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,api.mp.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,applog.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,client.video.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,cms.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,dispatcher.upmc.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,huichuan.sm.cn,AD-BAN
  - DOMAIN-SUFFIX,log.cs.pp.cn,AD-BAN
  - DOMAIN-SUFFIX,m.uczzd.cn,AD-BAN
  - DOMAIN-SUFFIX,patriot.cs.pp.cn,AD-BAN
  - DOMAIN-SUFFIX,puds.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,server.m.pp.cn,AD-BAN
  - DOMAIN-SUFFIX,track.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,u.uc123.com,AD-BAN
  - DOMAIN-SUFFIX,u.ucfly.com,AD-BAN
  - DOMAIN-SUFFIX,uc.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,ucsec.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,ucsec1.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,aoodoo.feng.com,AD-BAN
  - DOMAIN-SUFFIX,fengbuy.com,AD-BAN
  - DOMAIN-SUFFIX,push.feng.com,AD-BAN
  - DOMAIN-SUFFIX,we.tm,AD-BAN
  - DOMAIN-SUFFIX,yes1.feng.com,AD-BAN
  - DOMAIN-SUFFIX,ad.docer.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,adm.zookingsoft.com,AD-BAN
  - DOMAIN-SUFFIX,bannera.kingsoft-office-service.com,AD-BAN
  - DOMAIN-SUFFIX,bole.shangshufang.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,counter.kingsoft.com,AD-BAN
  - DOMAIN-SUFFIX,docerad.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,gou.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,hoplink.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,ic.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,img.gou.wpscdn.cn,AD-BAN
  - DOMAIN-SUFFIX,info.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,ios-informationplatform.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,minfo.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,mo.res.wpscdn.cn,AD-BAN
  - DOMAIN-SUFFIX,news.docer.com,AD-BAN
  - DOMAIN-SUFFIX,notify.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,pc.uf.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,pcfg.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,pixiu.shangshufang.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,push.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,rating6.kingsoft-office-service.com,AD-BAN
  - DOMAIN-SUFFIX,up.wps.kingsoft.com,AD-BAN
  - DOMAIN-SUFFIX,wpsweb-dc.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,c.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,cdsget.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,news-imgpb.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,wifiapidd.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,wkanc.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,adse.ximalaya.com,AD-BAN
  - DOMAIN-SUFFIX,linkeye.ximalaya.com,AD-BAN
  - DOMAIN-SUFFIX,location.ximalaya.com,AD-BAN
  - DOMAIN-SUFFIX,xdcs-collector.ximalaya.com,AD-BAN
  - DOMAIN-SUFFIX,biz5.kankan.com,AD-BAN
  - DOMAIN-SUFFIX,float.kankan.com,AD-BAN
  - DOMAIN-SUFFIX,hub5btmain.sandai.net,AD-BAN
  - DOMAIN-SUFFIX,hub5emu.sandai.net,AD-BAN
  - DOMAIN-SUFFIX,logic.cpm.cm.kankan.com,AD-BAN
  - DOMAIN-SUFFIX,upgrade.xl9.xunlei.com,AD-BAN
  - DOMAIN-SUFFIX,ad.wretch.cc,AD-BAN
  - DOMAIN-SUFFIX,ads.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,adserver.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,adss.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.query.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,ane.yahoo.co.jp,AD-BAN
  - DOMAIN-SUFFIX,ard.yahoo.co.jp,AD-BAN
  - DOMAIN-SUFFIX,beap-bc.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,clicks.beap.bc.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,comet.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,doubleplay-conf-yql.media.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,flurry.com,AD-BAN
  - DOMAIN-SUFFIX,gemini.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,geo.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,js-apac-ss.ysm.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,locdrop.query.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,onepush.query.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,p3p.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,partnerads.ysm.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,ws.progrss.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,yads.yahoo.co.jp,AD-BAN
  - DOMAIN-SUFFIX,ybp.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,shrek.6.cn,AD-BAN
  - DOMAIN-SUFFIX,simba.6.cn,AD-BAN
  - DOMAIN-SUFFIX,union.6.cn,AD-BAN
  - DOMAIN-SUFFIX,logger.baofeng.com,AD-BAN
  - DOMAIN-SUFFIX,xs.houyi.baofeng.net,AD-BAN
  - DOMAIN-SUFFIX,dotcounter.douyutv.com,AD-BAN
  - DOMAIN-SUFFIX,api.newad.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,exp.3g.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,game.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,iis3g.deliver.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,mfp.deliver.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,stadig.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,adm.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,jobsfe.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,po.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,pub.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,pv.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,stat.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,ad.m.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,afp.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,c.uaa.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,cloudpush.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,cm.passport.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,cupid.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,emoticon.sns.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,gamecenter.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,ifacelog.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,mbdlog.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,meta.video.qiyi.com,AD-BAN
  - DOMAIN-SUFFIX,msg.71.am,AD-BAN
  - DOMAIN-SUFFIX,msg1.video.qiyi.com,AD-BAN
  - DOMAIN-SUFFIX,msg2.video.qiyi.com,AD-BAN
  - DOMAIN-SUFFIX,paopao.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,paopaod.qiyipic.com,AD-BAN
  - DOMAIN-SUFFIX,policy.video.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,yuedu.iqiyi.com,AD-BAN
  - IP-CIDR,101.227.200.0/24,AD-BAN,no-resolve
  - IP-CIDR,101.227.200.11/32,AD-BAN,no-resolve
  - IP-CIDR,101.227.200.28/32,AD-BAN,no-resolve
  - IP-CIDR,101.227.97.240/32,AD-BAN,no-resolve
  - IP-CIDR,124.192.153.42/32,AD-BAN,no-resolve
  - DOMAIN-SUFFIX,gug.ku6cdn.com,AD-BAN
  - DOMAIN-SUFFIX,pq.stat.ku6.com,AD-BAN
  - DOMAIN-SUFFIX,st.vq.ku6.cn,AD-BAN
  - DOMAIN-SUFFIX,static.ku6.com,AD-BAN
  - DOMAIN-SUFFIX,1.letvlive.com,AD-BAN
  - DOMAIN-SUFFIX,2.letvlive.com,AD-BAN
  - DOMAIN-SUFFIX,ark.letv.com,AD-BAN
  - DOMAIN-SUFFIX,dc.letv.com,AD-BAN
  - DOMAIN-SUFFIX,fz.letv.com,AD-BAN
  - DOMAIN-SUFFIX,g3.letv.com,AD-BAN
  - DOMAIN-SUFFIX,game.letvstore.com,AD-BAN
  - DOMAIN-SUFFIX,i0.letvimg.com,AD-BAN
  - DOMAIN-SUFFIX,i3.letvimg.com,AD-BAN
  - DOMAIN-SUFFIX,minisite.letv.com,AD-BAN
  - DOMAIN-SUFFIX,n.mark.letv.com,AD-BAN
  - DOMAIN-SUFFIX,pro.hoye.letv.com,AD-BAN
  - DOMAIN-SUFFIX,pro.letv.com,AD-BAN
  - DOMAIN-SUFFIX,stat.letv.com,AD-BAN
  - DOMAIN-SUFFIX,static.app.m.letv.com,AD-BAN
  - DOMAIN-SUFFIX,click.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,da.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,da.mgtv.com,AD-BAN
  - DOMAIN-SUFFIX,log.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,log.v2.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,p2.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,res.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,888.tv.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,adnet.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,ads.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,aty.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,aty.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,bd.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,click.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,click2.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,ctr.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,epro.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,epro.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,go.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,golden1.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,golden1.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,hui.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,inte.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,inte.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,inte.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,lm.tv.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,lu.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,pb.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,push.tv.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,pv.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,pv.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,pv.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,theta.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,um.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,uranus.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,uranus.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,wan.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,wl.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,yule.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,afp.pplive.com,AD-BAN
  - DOMAIN-SUFFIX,app.aplus.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,as.aplus.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,asimgs.pplive.cn,AD-BAN
  - DOMAIN-SUFFIX,de.as.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,jp.as.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,pp2.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,stat.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,btrace.video.qq.com,AD-BAN
  - DOMAIN-SUFFIX,c.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,dp3.qq.com,AD-BAN
  - DOMAIN-SUFFIX,livep.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,lives.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,livew.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,mcgi.v.qq.com,AD-BAN
  - DOMAIN-SUFFIX,mdevstat.qqlive.qq.com,AD-BAN
  - DOMAIN-SUFFIX,omgmta1.qq.com,AD-BAN
  - DOMAIN-SUFFIX,p.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,rcgi.video.qq.com,AD-BAN
  - DOMAIN-SUFFIX,t.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,u.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,a-dxk.play.api.3g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,actives.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ad.api.3g.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,ad.api.3g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ad.api.mobile.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ad.mobile.youku.com,AD-BAN
  - DOMAIN-SUFFIX,adcontrol.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,adplay.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,b.smartvideo.youku.com,AD-BAN
  - DOMAIN-SUFFIX,c.yes.youku.com,AD-BAN
  - DOMAIN-SUFFIX,dev-push.m.youku.com,AD-BAN
  - DOMAIN-SUFFIX,dl.g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,dmapp.youku.com,AD-BAN
  - DOMAIN-SUFFIX,e.stat.ykimg.com,AD-BAN
  - DOMAIN-SUFFIX,gamex.mobile.youku.com,AD-BAN
  - DOMAIN-SUFFIX,goods.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,hudong.pl.youku.com,AD-BAN
  - DOMAIN-SUFFIX,hz.youku.com,AD-BAN
  - DOMAIN-SUFFIX,iwstat.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,iyes.youku.com,AD-BAN
  - DOMAIN-SUFFIX,l.ykimg.com,AD-BAN
  - DOMAIN-SUFFIX,l.youku.com,AD-BAN
  - DOMAIN-SUFFIX,lstat.youku.com,AD-BAN
  - DOMAIN-SUFFIX,lvip.youku.com,AD-BAN
  - DOMAIN-SUFFIX,mobilemsg.youku.com,AD-BAN
  - DOMAIN-SUFFIX,msg.youku.com,AD-BAN
  - DOMAIN-SUFFIX,myes.youku.com,AD-BAN
  - DOMAIN-SUFFIX,nstat.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,p-log.ykimg.com,AD-BAN
  - DOMAIN-SUFFIX,p.l.ykimg.com,AD-BAN
  - DOMAIN-SUFFIX,p.l.youku.com,AD-BAN
  - DOMAIN-SUFFIX,passport-log.youku.com,AD-BAN
  - DOMAIN-SUFFIX,push.m.youku.com,AD-BAN
  - DOMAIN-SUFFIX,r.l.youku.com,AD-BAN
  - DOMAIN-SUFFIX,s.p.youku.com,AD-BAN
  - DOMAIN-SUFFIX,sdk.m.youku.com,AD-BAN
  - DOMAIN-SUFFIX,stat.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,stat.youku.com,AD-BAN
  - DOMAIN-SUFFIX,stats.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,store.tv.api.3g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,store.xl.api.3g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,tdrec.youku.com,AD-BAN
  - DOMAIN-SUFFIX,test.ott.youku.com,AD-BAN
  - DOMAIN-SUFFIX,v.l.youku.com,AD-BAN
  - DOMAIN-SUFFIX,val.api.youku.com,AD-BAN
  - DOMAIN-SUFFIX,wan.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ykatr.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ykrec.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ykrectab.youku.com,AD-BAN
  - IP-CIDR,117.177.248.17/32,AD-BAN,no-resolve
  - IP-CIDR,117.177.248.41/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.176.139/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.176.176/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.180/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.182/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.184/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.43/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.47/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.80/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.182.101/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.182.102/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.182.11/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.182.52/32,AD-BAN,no-resolve
  - DOMAIN-SUFFIX,azabu-u.ac.jp,AD-BAN
  - DOMAIN-SUFFIX,couchcoaster.jp,AD-BAN
  - DOMAIN-SUFFIX,delivery.dmkt-sp.jp,AD-BAN
  - DOMAIN-SUFFIX,ehg-youtube.hitbox.com,AD-BAN
  - DOMAIN-SUFFIX,nichibenren.or.jp,AD-BAN
  - DOMAIN-SUFFIX,nicorette.co.kr,AD-BAN
  - DOMAIN-SUFFIX,ssl-youtube.2cnt.net,AD-BAN
  - DOMAIN-SUFFIX,youtube.112.2o7.net,AD-BAN
  - DOMAIN-SUFFIX,youtube.2cnt.net,AD-BAN
  - DOMAIN-SUFFIX,acsystem.wasu.tv,AD-BAN
  - DOMAIN-SUFFIX,ads.cdn.tvb.com,AD-BAN
  - DOMAIN-SUFFIX,ads.wasu.tv,AD-BAN
  - DOMAIN-SUFFIX,afp.wasu.tv,AD-BAN
  - DOMAIN-SUFFIX,c.algovid.com,AD-BAN
  - DOMAIN-SUFFIX,gg.jtertp.com,AD-BAN
  - DOMAIN-SUFFIX,gridsum-vd.cntv.cn,AD-BAN
  - DOMAIN-SUFFIX,kwflvcdn.000dn.com,AD-BAN
  - DOMAIN-SUFFIX,logstat.t.sfht.com,AD-BAN
  - DOMAIN-SUFFIX,match.rtbidder.net,AD-BAN
  - DOMAIN-SUFFIX,n-st.vip.com,AD-BAN
  - DOMAIN-SUFFIX,pop.uusee.com,AD-BAN
  - DOMAIN-SUFFIX,static.duoshuo.com,AD-BAN
  - DOMAIN-SUFFIX,t.cr-nielsen.com,AD-BAN
  - DOMAIN-SUFFIX,terren.cntv.cn,AD-BAN
  - DOMAIN-SUFFIX,1.win7china.com,AD-BAN
  - DOMAIN-SUFFIX,168.it168.com,AD-BAN
  - DOMAIN-SUFFIX,2.win7china.com,AD-BAN
  - DOMAIN-SUFFIX,801.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,801.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,803.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,803.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,806.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,806.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,808.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,808.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,92x.tumblr.com,AD-BAN
  - DOMAIN-SUFFIX,a1.itc.cn,AD-BAN
  - DOMAIN-SUFFIX,ad-channel.wikawika.xyz,AD-BAN
  - DOMAIN-SUFFIX,ad-display.wikawika.xyz,AD-BAN
  - DOMAIN-SUFFIX,ad.12306.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.3.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.95306.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.caiyunapp.com,AD-BAN
  - DOMAIN-SUFFIX,ad.cctv.com,AD-BAN
  - DOMAIN-SUFFIX,ad.cmvideo.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.csdn.net,AD-BAN
  - DOMAIN-SUFFIX,ad.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,ad.house365.com,AD-BAN
  - DOMAIN-SUFFIX,ad.thepaper.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.unimhk.com,AD-BAN
  - DOMAIN-SUFFIX,adadmin.house365.com,AD-BAN
  - DOMAIN-SUFFIX,adhome.1fangchan.com,AD-BAN
  - DOMAIN-SUFFIX,adm.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,ads.csdn.net,AD-BAN
  - DOMAIN-SUFFIX,ads.feedly.com,AD-BAN
  - DOMAIN-SUFFIX,ads.genieessp.com,AD-BAN
  - DOMAIN-SUFFIX,ads.house365.com,AD-BAN
  - DOMAIN-SUFFIX,ads.linkedin.com,AD-BAN
  - DOMAIN-SUFFIX,adshownew.it168.com,AD-BAN
  - DOMAIN-SUFFIX,adv.ccb.com,AD-BAN
  - DOMAIN-SUFFIX,advert.api.thejoyrun.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,api-deal.kechenggezi.com,AD-BAN
  - DOMAIN-SUFFIX,api-z.weidian.com,AD-BAN
  - DOMAIN-SUFFIX,app-monitor.ele.me,AD-BAN
  - DOMAIN-SUFFIX,bat.bing.com,AD-BAN
  - DOMAIN-SUFFIX,bd1.52che.com,AD-BAN
  - DOMAIN-SUFFIX,bd2.52che.com,AD-BAN
  - DOMAIN-SUFFIX,bdj.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,bdj.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,beacon.tingyun.com,AD-BAN
  - DOMAIN-SUFFIX,cdn.jiuzhilan.com,AD-BAN
  - DOMAIN-SUFFIX,click.cheshi-img.com,AD-BAN
  - DOMAIN-SUFFIX,click.cheshi.com,AD-BAN
  - DOMAIN-SUFFIX,click.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,click.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,click.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,client-api.ele.me,AD-BAN
  - DOMAIN-SUFFIX,collector.githubapp.com,AD-BAN
  - DOMAIN-SUFFIX,counter.csdn.net,AD-BAN
  - DOMAIN-SUFFIX,d0.xcar.com.cn,AD-BAN
  - DOMAIN-SUFFIX,de.soquair.com,AD-BAN
  - DOMAIN-SUFFIX,dol.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,dol.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,dw.xcar.com.cn,AD-BAN
  - DOMAIN-SUFFIX,e.nexac.com,AD-BAN
  - DOMAIN-SUFFIX,eq.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,exp.17wo.cn,AD-BAN
  - DOMAIN-SUFFIX,game.51yund.com,AD-BAN
  - DOMAIN-SUFFIX,ganjituiguang.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,grand.ele.me,AD-BAN
  - DOMAIN-SUFFIX,hosting.miarroba.info,AD-BAN
  - DOMAIN-SUFFIX,iadsdk.apple.com,AD-BAN
  - DOMAIN-SUFFIX,image.gentags.com,AD-BAN
  - DOMAIN-SUFFIX,its-dori.tumblr.com,AD-BAN
  - DOMAIN-SUFFIX,log.outbrain.com,AD-BAN
  - DOMAIN-SUFFIX,m.12306media.com,AD-BAN
  - DOMAIN-SUFFIX,media.cheshi-img.com,AD-BAN
  - DOMAIN-SUFFIX,media.cheshi.com,AD-BAN
  - DOMAIN-SUFFIX,mobile-pubt.ele.me,AD-BAN
  - DOMAIN-SUFFIX,mobileads.msn.com,AD-BAN
  - DOMAIN-SUFFIX,n.cosbot.cn,AD-BAN
  - DOMAIN-SUFFIX,newton-api.ele.me,AD-BAN
  - DOMAIN-SUFFIX,ozone.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,pdl.gionee.com,AD-BAN
  - DOMAIN-SUFFIX,pica-juicy.picacomic.com,AD-BAN
  - DOMAIN-SUFFIX,pixel.wp.com,AD-BAN
  - DOMAIN-SUFFIX,pub.mop.com,AD-BAN
  - DOMAIN-SUFFIX,push.wandoujia.com,AD-BAN
  - DOMAIN-SUFFIX,pv.cheshi-img.com,AD-BAN
  - DOMAIN-SUFFIX,pv.cheshi.com,AD-BAN
  - DOMAIN-SUFFIX,pv.xcar.com.cn,AD-BAN
  - DOMAIN-SUFFIX,qdp.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,res.gwifi.com.cn,AD-BAN
  - DOMAIN-SUFFIX,ssp.kssws.ks-cdn.com,AD-BAN
  - DOMAIN-SUFFIX,sta.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,stat.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,stat.it168.com,AD-BAN
  - DOMAIN-SUFFIX,stats.chinaz.com,AD-BAN
  - DOMAIN-SUFFIX,stats.developingperspective.com,AD-BAN
  - DOMAIN-SUFFIX,track.hujiang.com,AD-BAN
  - DOMAIN-SUFFIX,tracker.yhd.com,AD-BAN
  - DOMAIN-SUFFIX,tralog.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,up.qingdaonews.com,AD-BAN
  - DOMAIN-SUFFIX,vaserviece.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,265.com,DC
  - DOMAIN-SUFFIX,2mdn.net,DC
  - DOMAIN-SUFFIX,alt1-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt2-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt3-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt4-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt5-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt6-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt7-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt8-mtalk.google.com,DC
  - DOMAIN-SUFFIX,app-measurement.com,DC
  - DOMAIN-SUFFIX,cache.pack.google.com,DC
  - DOMAIN-SUFFIX,clickserve.dartsearch.net,DC
  - DOMAIN-SUFFIX,crl.pki.goog,DC
  - DOMAIN-SUFFIX,dl.google.com,DC
  - DOMAIN-SUFFIX,dl.l.google.com,DC
  - DOMAIN-SUFFIX,googletagmanager.com,DC
  - DOMAIN-SUFFIX,googletagservices.com,DC
  - DOMAIN-SUFFIX,gtm.oasisfeng.com,DC
  - DOMAIN-SUFFIX,mtalk.google.com,DC
  - DOMAIN-SUFFIX,ocsp.pki.goog,DC
  - DOMAIN-SUFFIX,recaptcha.net,DC
  - DOMAIN-SUFFIX,safebrowsing-cache.google.com,DC
  - DOMAIN-SUFFIX,settings.crashlytics.com,DC
  - DOMAIN-SUFFIX,ssl-google-analytics.l.google.com,DC
  - DOMAIN-SUFFIX,toolbarqueries.google.com,DC
  - DOMAIN-SUFFIX,tools.google.com,DC
  - DOMAIN-SUFFIX,tools.l.google.com,DC
  - DOMAIN-SUFFIX,www-googletagmanager.l.google.com,DC
  - DOMAIN,csgo.wmsj.cn,DC
  - DOMAIN,dl.steam.clngaa.com,DC
  - DOMAIN,dl.steam.ksyna.com,DC
  - DOMAIN,dota2.wmsj.cn,DC
  - DOMAIN,st.dl.bscstorage.net,DC
  - DOMAIN,st.dl.eccdnx.com,DC
  - DOMAIN,st.dl.pinyuncloud.com,DC
  - DOMAIN,steampipe.steamcontent.tnkjmec.com,DC
  - DOMAIN,steampowered.com.8686c.com,DC
  - DOMAIN,steamstatic.com.8686c.com,DC
  - DOMAIN,wmsjsteam.com,DC
  - DOMAIN,xz.pphimalayanrt.com,DC
  - DOMAIN-SUFFIX,cm.steampowered.com,DC
  - DOMAIN-SUFFIX,steamchina.com,DC
  - DOMAIN-SUFFIX,steamcontent.com,DC
  - DOMAIN-SUFFIX,steamusercontent.com,DC
  - DOMAIN,bahamut.akamaized.net,BILI
  - DOMAIN,gamer-cds.cdn.hinet.net,BILI
  - DOMAIN,gamer2-cds.cdn.hinet.net,BILI
  - DOMAIN-SUFFIX,bahamut.com.tw,BILI
  - DOMAIN-SUFFIX,gamer.com.tw,BILI
  - DOMAIN,p-bstarstatic.akamaized.net,BILI
  - DOMAIN,p.bstarstatic.com,BILI
  - DOMAIN,upos-bstar-mirrorakam.akamaized.net,BILI
  - DOMAIN,upos-bstar1-mirrorakam.akamaized.net,BILI
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,BILI
  - DOMAIN-SUFFIX,acgvideo.com,BILI
  - DOMAIN-SUFFIX,bilibili.com,BILI
  - DOMAIN-SUFFIX,bilibili.tv,BILI
  - IP-CIDR,45.43.32.234/32,BILI,no-resolve
  - IP-CIDR,103.151.150.0/23,BILI,no-resolve
  - IP-CIDR,119.29.29.29/32,BILI,no-resolve
  - IP-CIDR,128.1.62.200/32,BILI,no-resolve
  - IP-CIDR,128.1.62.201/32,BILI,no-resolve
  - IP-CIDR,150.116.92.250/32,BILI,no-resolve
  - IP-CIDR,164.52.33.178/32,BILI,no-resolve
  - IP-CIDR,164.52.33.182/32,BILI,no-resolve
  - IP-CIDR,164.52.76.18/32,BILI,no-resolve
  - IP-CIDR,203.107.1.33/32,BILI,no-resolve
  - IP-CIDR,203.107.1.34/32,BILI,no-resolve
  - IP-CIDR,203.107.1.65/32,BILI,no-resolve
  - IP-CIDR,203.107.1.66/32,BILI,no-resolve
  - DOMAIN,apiintl.biliapi.net,BILI
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,BILI
  - DOMAIN-SUFFIX,acg.tv,BILI
  - DOMAIN-SUFFIX,acgvideo.com,BILI
  - DOMAIN-SUFFIX,b23.tv,BILI
  - DOMAIN-SUFFIX,bigfun.cn,BILI
  - DOMAIN-SUFFIX,bigfunapp.cn,BILI
  - DOMAIN-SUFFIX,biliapi.com,BILI
  - DOMAIN-SUFFIX,biliapi.net,BILI
  - DOMAIN-SUFFIX,bilibili.co,BILI
  - DOMAIN-SUFFIX,bilibili.com,BILI
  - DOMAIN-SUFFIX,bilibili.tv,BILI
  - DOMAIN-SUFFIX,biligame.com,BILI
  - DOMAIN-SUFFIX,biligame.net,BILI
  - DOMAIN-SUFFIX,biliintl.co,BILI
  - DOMAIN-SUFFIX,bilivideo.cn,BILI
  - DOMAIN-SUFFIX,bilivideo.com,BILI
  - DOMAIN-SUFFIX,hdslb.com,BILI
  - DOMAIN-SUFFIX,im9.com,BILI
  - DOMAIN-SUFFIX,smtcdns.net,BILI
  - DOMAIN,apiintl.biliapi.net,BILI
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,BILI
  - DOMAIN-SUFFIX,acg.tv,BILI
  - DOMAIN-SUFFIX,acgvideo.com,BILI
  - DOMAIN-SUFFIX,b23.tv,BILI
  - DOMAIN-SUFFIX,bigfun.cn,BILI
  - DOMAIN-SUFFIX,bigfunapp.cn,BILI
  - DOMAIN-SUFFIX,biliapi.com,BILI
  - DOMAIN-SUFFIX,biliapi.net,BILI
  - DOMAIN-SUFFIX,bilibili.com,BILI
  - DOMAIN-SUFFIX,bilibili.tv,BILI
  - DOMAIN-SUFFIX,biligame.com,BILI
  - DOMAIN-SUFFIX,biligame.net,BILI
  - DOMAIN-SUFFIX,bilivideo.cn,BILI
  - DOMAIN-SUFFIX,bilivideo.com,BILI
  - DOMAIN-SUFFIX,hdslb.com,BILI
  - DOMAIN-SUFFIX,im9.com,BILI
  - DOMAIN-SUFFIX,smtcdns.net,BILI
  - DOMAIN,intel-cache.m.iqiyi.com,BILI
  - DOMAIN,intel-cache.video.iqiyi.com,BILI
  - DOMAIN,intl-rcd.iqiyi.com,BILI
  - DOMAIN,intl-subscription.iqiyi.com,BILI
  - DOMAIN-SUFFIX,inter.iqiyi.com,BILI
  - DOMAIN-SUFFIX,inter.ptqy.gitv.tv,BILI
  - DOMAIN-SUFFIX,intl.iqiyi.com,BILI
  - DOMAIN-SUFFIX,iq.com,BILI
  - IP-CIDR,23.40.241.251/32,BILI,no-resolve
  - IP-CIDR,23.40.242.10/32,BILI,no-resolve
  - IP-CIDR,103.44.56.0/22,BILI,no-resolve
  - IP-CIDR,118.26.32.0/23,BILI,no-resolve
  - IP-CIDR,118.26.120.0/24,BILI,no-resolve
  - IP-CIDR,223.119.62.225/28,BILI,no-resolve
  - DOMAIN-SUFFIX,api.mob.app.letv.com,BILI
  - DOMAIN-SUFFIX,v.smtcdns.com,BILI
  - DOMAIN-SUFFIX,vv.video.qq.com,BILI
  - DOMAIN-SUFFIX,youku.com,BILI
  - IP-CIDR,106.11.0.0/16,BILI,no-resolve
  - DOMAIN-SUFFIX,zuoyebang.com,DC
  - DOMAIN-SUFFIX,steampy.com,DC
  - DOMAIN-SUFFIX,qq.com,DC
  - DOMAIN-SUFFIX,gushiwen.cn,DC
  - DOMAIN-SUFFIX,13th.tech,DC
  - DOMAIN-SUFFIX,423down.com,DC
  - DOMAIN-SUFFIX,bokecc.com,DC
  - DOMAIN-SUFFIX,chaipip.com,DC
  - DOMAIN-SUFFIX,chinaplay.store,DC
  - DOMAIN-SUFFIX,hrtsea.com,DC
  - DOMAIN-SUFFIX,kaikeba.com,DC
  - DOMAIN-SUFFIX,laomo.me,DC
  - DOMAIN-SUFFIX,mpyit.com,DC
  - DOMAIN-SUFFIX,msftconnecttest.com,DC
  - DOMAIN-SUFFIX,msftncsi.com,DC
  - DOMAIN-SUFFIX,qupu123.com,DC
  - DOMAIN-SUFFIX,pdfwifi.com,DC
  - DOMAIN-SUFFIX,zhenguanyu.biz,DC
  - DOMAIN-SUFFIX,zhenguanyu.com,DC
  - DOMAIN-SUFFIX,snapdrop.net,DC
  - DOMAIN-SUFFIX,tebex.io,DC
  - DOMAIN-SUFFIX,cn,DC
  - DOMAIN-SUFFIX,xn--fiqs8s,DC
  - DOMAIN-SUFFIX,xn--55qx5d,DC
  - DOMAIN-SUFFIX,xn--io0a7i,DC
  - DOMAIN-KEYWORD,360buy,DC
  - DOMAIN-KEYWORD,alicdn,DC
  - DOMAIN-KEYWORD,alimama,DC
  - DOMAIN-KEYWORD,alipay,DC
  - DOMAIN-KEYWORD,appzapp,DC
  - DOMAIN-KEYWORD,baidupcs,DC
  - DOMAIN-KEYWORD,bilibili,DC
  - DOMAIN-KEYWORD,ccgslb,DC
  - DOMAIN-KEYWORD,chinacache,DC
  - DOMAIN-KEYWORD,duobao,DC
  - DOMAIN-KEYWORD,jdpay,DC
  - DOMAIN-KEYWORD,moke,DC
  - DOMAIN-KEYWORD,qhimg,DC
  - DOMAIN-KEYWORD,vpimg,DC
  - DOMAIN-KEYWORD,xiami,DC
  - DOMAIN-KEYWORD,xiaomi,DC
  - DOMAIN-SUFFIX,360.com,DC
  - DOMAIN-SUFFIX,360kuai.com,DC
  - DOMAIN-SUFFIX,360safe.com,DC
  - DOMAIN-SUFFIX,dhrest.com,DC
  - DOMAIN-SUFFIX,qhres.com,DC
  - DOMAIN-SUFFIX,qhstatic.com,DC
  - DOMAIN-SUFFIX,qhupdate.com,DC
  - DOMAIN-SUFFIX,so.com,DC
  - DOMAIN-SUFFIX,4399.com,DC
  - DOMAIN-SUFFIX,4399pk.com,DC
  - DOMAIN-SUFFIX,5054399.com,DC
  - DOMAIN-SUFFIX,img4399.com,DC
  - DOMAIN-SUFFIX,58.com,DC
  - DOMAIN-SUFFIX,1688.com,DC
  - DOMAIN-SUFFIX,aliapp.org,DC
  - DOMAIN-SUFFIX,alibaba.com,DC
  - DOMAIN-SUFFIX,alibabacloud.com,DC
  - DOMAIN-SUFFIX,alibabausercontent.com,DC
  - DOMAIN-SUFFIX,alicdn.com,DC
  - DOMAIN-SUFFIX,alicloudccp.com,DC
  - DOMAIN-SUFFIX,aliexpress.com,DC
  - DOMAIN-SUFFIX,aliimg.com,DC
  - DOMAIN-SUFFIX,alikunlun.com,DC
  - DOMAIN-SUFFIX,alipay.com,DC
  - DOMAIN-SUFFIX,alipayobjects.com,DC
  - DOMAIN-SUFFIX,alisoft.com,DC
  - DOMAIN-SUFFIX,aliyun.com,DC
  - DOMAIN-SUFFIX,aliyuncdn.com,DC
  - DOMAIN-SUFFIX,aliyuncs.com,DC
  - DOMAIN-SUFFIX,aliyundrive.com,DC
  - DOMAIN-SUFFIX,aliyundrive.net,DC
  - DOMAIN-SUFFIX,amap.com,DC
  - DOMAIN-SUFFIX,autonavi.com,DC
  - DOMAIN-SUFFIX,dingtalk.com,DC
  - DOMAIN-SUFFIX,ele.me,DC
  - DOMAIN-SUFFIX,hichina.com,DC
  - DOMAIN-SUFFIX,mmstat.com,DC
  - DOMAIN-SUFFIX,mxhichina.com,DC
  - DOMAIN-SUFFIX,soku.com,DC
  - DOMAIN-SUFFIX,taobao.com,DC
  - DOMAIN-SUFFIX,taobaocdn.com,DC
  - DOMAIN-SUFFIX,tbcache.com,DC
  - DOMAIN-SUFFIX,tbcdn.com,DC
  - DOMAIN-SUFFIX,tmall.com,DC
  - DOMAIN-SUFFIX,tmall.hk,DC
  - DOMAIN-SUFFIX,ucweb.com,DC
  - DOMAIN-SUFFIX,xiami.com,DC
  - DOMAIN-SUFFIX,xiami.net,DC
  - DOMAIN-SUFFIX,ykimg.com,DC
  - DOMAIN-SUFFIX,youku.com,DC
  - DOMAIN-SUFFIX,baidu.com,DC
  - DOMAIN-SUFFIX,baidubcr.com,DC
  - DOMAIN-SUFFIX,baidupcs.com,DC
  - DOMAIN-SUFFIX,baidustatic.com,DC
  - DOMAIN-SUFFIX,bcebos.com,DC
  - DOMAIN-SUFFIX,bdimg.com,DC
  - DOMAIN-SUFFIX,bdstatic.com,DC
  - DOMAIN-SUFFIX,bdurl.net,DC
  - DOMAIN-SUFFIX,hao123.com,DC
  - DOMAIN-SUFFIX,hao123img.com,DC
  - DOMAIN-SUFFIX,jomodns.com,DC
  - DOMAIN-SUFFIX,yunjiasu-cdn.net,DC
  - DOMAIN-SUFFIX,acg.tv,DC
  - DOMAIN-SUFFIX,acgvideo.com,DC
  - DOMAIN-SUFFIX,b23.tv,DC
  - DOMAIN-SUFFIX,bigfun.cn,DC
  - DOMAIN-SUFFIX,bigfunapp.cn,DC
  - DOMAIN-SUFFIX,biliapi.com,DC
  - DOMAIN-SUFFIX,biliapi.net,DC
  - DOMAIN-SUFFIX,bilibili.com,DC
  - DOMAIN-SUFFIX,bilibili.co,DC
  - DOMAIN-SUFFIX,biliintl.co,DC
  - DOMAIN-SUFFIX,biligame.com,DC
  - DOMAIN-SUFFIX,biligame.net,DC
  - DOMAIN-SUFFIX,bilivideo.com,DC
  - DOMAIN-SUFFIX,bilivideo.cn,DC
  - DOMAIN-SUFFIX,hdslb.com,DC
  - DOMAIN-SUFFIX,im9.com,DC
  - DOMAIN-SUFFIX,smtcdns.net,DC
  - DOMAIN-SUFFIX,amemv.com,DC
  - DOMAIN-SUFFIX,bdxiguaimg.com,DC
  - DOMAIN-SUFFIX,bdxiguastatic.com,DC
  - DOMAIN-SUFFIX,byted-static.com,DC
  - DOMAIN-SUFFIX,bytedance.com,DC
  - DOMAIN-SUFFIX,bytedance.net,DC
  - DOMAIN-SUFFIX,bytedns.net,DC
  - DOMAIN-SUFFIX,bytednsdoc.com,DC
  - DOMAIN-SUFFIX,bytegoofy.com,DC
  - DOMAIN-SUFFIX,byteimg.com,DC
  - DOMAIN-SUFFIX,bytescm.com,DC
  - DOMAIN-SUFFIX,bytetos.com,DC
  - DOMAIN-SUFFIX,bytexservice.com,DC
  - DOMAIN-SUFFIX,douyin.com,DC
  - DOMAIN-SUFFIX,douyincdn.com,DC
  - DOMAIN-SUFFIX,douyinpic.com,DC
  - DOMAIN-SUFFIX,douyinstatic.com,DC
  - DOMAIN-SUFFIX,douyinvod.com,DC
  - DOMAIN-SUFFIX,feelgood.cn,DC
  - DOMAIN-SUFFIX,feiliao.com,DC
  - DOMAIN-SUFFIX,gifshow.com,DC
  - DOMAIN-SUFFIX,huoshan.com,DC
  - DOMAIN-SUFFIX,huoshanzhibo.com,DC
  - DOMAIN-SUFFIX,ibytedapm.com,DC
  - DOMAIN-SUFFIX,iesdouyin.com,DC
  - DOMAIN-SUFFIX,ixigua.com,DC
  - DOMAIN-SUFFIX,kspkg.com,DC
  - DOMAIN-SUFFIX,pstatp.com,DC
  - DOMAIN-SUFFIX,snssdk.com,DC
  - DOMAIN-SUFFIX,toutiao.com,DC
  - DOMAIN-SUFFIX,toutiao13.com,DC
  - DOMAIN-SUFFIX,toutiaoapi.com,DC
  - DOMAIN-SUFFIX,toutiaocdn.com,DC
  - DOMAIN-SUFFIX,toutiaocdn.net,DC
  - DOMAIN-SUFFIX,toutiaocloud.com,DC
  - DOMAIN-SUFFIX,toutiaohao.com,DC
  - DOMAIN-SUFFIX,toutiaohao.net,DC
  - DOMAIN-SUFFIX,toutiaoimg.com,DC
  - DOMAIN-SUFFIX,toutiaopage.com,DC
  - DOMAIN-SUFFIX,wukong.com,DC
  - DOMAIN-SUFFIX,zijieapi.com,DC
  - DOMAIN-SUFFIX,zijieimg.com,DC
  - DOMAIN-SUFFIX,zjbyte.com,DC
  - DOMAIN-SUFFIX,zjcdn.com,DC
  - DOMAIN-SUFFIX,cctv.com,DC
  - DOMAIN-SUFFIX,cctvpic.com,DC
  - DOMAIN-SUFFIX,livechina.com,DC
  - DOMAIN-SUFFIX,21cn.com,DC
  - DOMAIN-SUFFIX,didialift.com,DC
  - DOMAIN-SUFFIX,didiglobal.com,DC
  - DOMAIN-SUFFIX,udache.com,DC
  - DOMAIN-SUFFIX,bytefcdnrd.com,DC
  - DOMAIN-SUFFIX,edgesrv.com,DC
  - DOMAIN-SUFFIX,douyu.com,DC
  - DOMAIN-SUFFIX,douyu.tv,DC
  - DOMAIN-SUFFIX,douyuscdn.com,DC
  - DOMAIN-SUFFIX,douyutv.com,DC
  - DOMAIN-SUFFIX,epicgames.com,DC
  - DOMAIN-SUFFIX,epicgames.dev,DC
  - DOMAIN-SUFFIX,helpshift.com,DC
  - DOMAIN-SUFFIX,paragon.com,DC
  - DOMAIN-SUFFIX,unrealengine.com,DC
  - DOMAIN-SUFFIX,dbankcdn.com,DC
  - DOMAIN-SUFFIX,hc-cdn.com,DC
  - DOMAIN-SUFFIX,hicloud.com,DC
  - DOMAIN-SUFFIX,hihonor.com,DC
  - DOMAIN-SUFFIX,huawei.com,DC
  - DOMAIN-SUFFIX,huaweicloud.com,DC
  - DOMAIN-SUFFIX,huaweishop.net,DC
  - DOMAIN-SUFFIX,hwccpc.com,DC
  - DOMAIN-SUFFIX,vmall.com,DC
  - DOMAIN-SUFFIX,vmallres.com,DC
  - DOMAIN-SUFFIX,allawnfs.com,DC
  - DOMAIN-SUFFIX,allawno.com,DC
  - DOMAIN-SUFFIX,allawntech.com,DC
  - DOMAIN-SUFFIX,coloros.com,DC
  - DOMAIN-SUFFIX,heytap.com,DC
  - DOMAIN-SUFFIX,heytapcs.com,DC
  - DOMAIN-SUFFIX,heytapdownload.com,DC
  - DOMAIN-SUFFIX,heytapimage.com,DC
  - DOMAIN-SUFFIX,heytapmobi.com,DC
  - DOMAIN-SUFFIX,oppo.com,DC
  - DOMAIN-SUFFIX,oppoer.me,DC
  - DOMAIN-SUFFIX,oppomobile.com,DC
  - DOMAIN-SUFFIX,iflyink.com,DC
  - DOMAIN-SUFFIX,iflyrec.com,DC
  - DOMAIN-SUFFIX,iflytek.com,DC
  - DOMAIN-SUFFIX,71.am,DC
  - DOMAIN-SUFFIX,71edge.com,DC
  - DOMAIN-SUFFIX,iqiyi.com,DC
  - DOMAIN-SUFFIX,iqiyipic.com,DC
  - DOMAIN-SUFFIX,ppsimg.com,DC
  - DOMAIN-SUFFIX,qiyi.com,DC
  - DOMAIN-SUFFIX,qiyipic.com,DC
  - DOMAIN-SUFFIX,qy.net,DC
  - DOMAIN-SUFFIX,360buy.com,DC
  - DOMAIN-SUFFIX,360buyimg.com,DC
  - DOMAIN-SUFFIX,jcloudcs.com,DC
  - DOMAIN-SUFFIX,jd.com,DC
  - DOMAIN-SUFFIX,jd.hk,DC
  - DOMAIN-SUFFIX,jdcloud.com,DC
  - DOMAIN-SUFFIX,jdpay.com,DC
  - DOMAIN-SUFFIX,paipai.com,DC
  - DOMAIN-SUFFIX,iciba.com,DC
  - DOMAIN-SUFFIX,ksosoft.com,DC
  - DOMAIN-SUFFIX,ksyun.com,DC
  - DOMAIN-SUFFIX,kuaishou.com,DC
  - DOMAIN-SUFFIX,yximgs.com,DC
  - DOMAIN-SUFFIX,meitu.com,DC
  - DOMAIN-SUFFIX,meitudata.com,DC
  - DOMAIN-SUFFIX,meitustat.com,DC
  - DOMAIN-SUFFIX,meipai.com,DC
  - DOMAIN-SUFFIX,le.com,DC
  - DOMAIN-SUFFIX,lecloud.com,DC
  - DOMAIN-SUFFIX,letv.com,DC
  - DOMAIN-SUFFIX,letvcloud.com,DC
  - DOMAIN-SUFFIX,letvimg.com,DC
  - DOMAIN-SUFFIX,letvlive.com,DC
  - DOMAIN-SUFFIX,letvstore.com,DC
  - DOMAIN-SUFFIX,hitv.com,DC
  - DOMAIN-SUFFIX,hunantv.com,DC
  - DOMAIN-SUFFIX,mgtv.com,DC
  - DOMAIN-SUFFIX,duokan.com,DC
  - DOMAIN-SUFFIX,mi-img.com,DC
  - DOMAIN-SUFFIX,mi.com,DC
  - DOMAIN-SUFFIX,miui.com,DC
  - DOMAIN-SUFFIX,xiaomi.com,DC
  - DOMAIN-SUFFIX,xiaomi.net,DC
  - DOMAIN-SUFFIX,xiaomicp.com,DC
  - DOMAIN-SUFFIX,126.com,DC
  - DOMAIN-SUFFIX,126.net,DC
  - DOMAIN-SUFFIX,127.net,DC
  - DOMAIN-SUFFIX,163.com,DC
  - DOMAIN-SUFFIX,163yun.com,DC
  - DOMAIN-SUFFIX,lofter.com,DC
  - DOMAIN-SUFFIX,netease.com,DC
  - DOMAIN-SUFFIX,ydstatic.com,DC
  - DOMAIN-SUFFIX,youdao.com,DC
  - DOMAIN-SUFFIX,pplive.com,DC
  - DOMAIN-SUFFIX,pptv.com,DC
  - DOMAIN-SUFFIX,pinduoduo.com,DC
  - DOMAIN-SUFFIX,yangkeduo.com,DC
  - DOMAIN-SUFFIX,leju.com,DC
  - DOMAIN-SUFFIX,miaopai.com,DC
  - DOMAIN-SUFFIX,sina.com,DC
  - DOMAIN-SUFFIX,sina.com.cn,DC
  - DOMAIN-SUFFIX,sina.cn,DC
  - DOMAIN-SUFFIX,sinaapp.com,DC
  - DOMAIN-SUFFIX,sinaapp.cn,DC
  - DOMAIN-SUFFIX,sinaimg.com,DC
  - DOMAIN-SUFFIX,sinaimg.cn,DC
  - DOMAIN-SUFFIX,weibo.com,DC
  - DOMAIN-SUFFIX,weibo.cn,DC
  - DOMAIN-SUFFIX,weibocdn.com,DC
  - DOMAIN-SUFFIX,weibocdn.cn,DC
  - DOMAIN-SUFFIX,xiaoka.tv,DC
  - DOMAIN-SUFFIX,go2map.com,DC
  - DOMAIN-SUFFIX,sogo.com,DC
  - DOMAIN-SUFFIX,sogou.com,DC
  - DOMAIN-SUFFIX,sogoucdn.com,DC
  - DOMAIN-SUFFIX,sohu-inc.com,DC
  - DOMAIN-SUFFIX,sohu.com,DC
  - DOMAIN-SUFFIX,sohucs.com,DC
  - DOMAIN-SUFFIX,sohuno.com,DC
  - DOMAIN-SUFFIX,sohurdc.com,DC
  - DOMAIN-SUFFIX,v-56.com,DC
  - DOMAIN-SUFFIX,playstation.com,DC
  - DOMAIN-SUFFIX,playstation.net,DC
  - DOMAIN-SUFFIX,playstationnetwork.com,DC
  - DOMAIN-SUFFIX,sony.com,DC
  - DOMAIN-SUFFIX,sonyentertainmentnetwork.com,DC
  - DOMAIN-SUFFIX,cm.steampowered.com,DC
  - DOMAIN-SUFFIX,steamcontent.com,DC
  - DOMAIN-SUFFIX,steamusercontent.com,DC
  - DOMAIN-SUFFIX,steamchina.com,DC
  - DOMAIN,csgo.wmsj.cn,DC
  - DOMAIN,dota2.wmsj.cn,DC
  - DOMAIN,wmsjsteam.com,DC
  - DOMAIN,dl.steam.clngaa.com,DC
  - DOMAIN,dl.steam.ksyna.com,DC
  - DOMAIN,st.dl.bscstorage.net,DC
  - DOMAIN,st.dl.eccdnx.com,DC
  - DOMAIN,st.dl.pinyuncloud.com,DC
  - DOMAIN,xz.pphimalayanrt.com,DC
  - DOMAIN,steampipe.steamcontent.tnkjmec.com,DC
  - DOMAIN,steampowered.com.8686c.com,DC
  - DOMAIN,steamstatic.com.8686c.com,DC
  - DOMAIN-SUFFIX,foxmail.com,DC
  - DOMAIN-SUFFIX,gtimg.com,DC
  - DOMAIN-SUFFIX,idqqimg.com,DC
  - DOMAIN-SUFFIX,igamecj.com,DC
  - DOMAIN-SUFFIX,myapp.com,DC
  - DOMAIN-SUFFIX,myqcloud.com,DC
  - DOMAIN-SUFFIX,qq.com,DC
  - DOMAIN-SUFFIX,qqmail.com,DC
  - DOMAIN-SUFFIX,qqurl.com,DC
  - DOMAIN-SUFFIX,smtcdns.com,DC
  - DOMAIN-SUFFIX,smtcdns.net,DC
  - DOMAIN-SUFFIX,soso.com,DC
  - DOMAIN-SUFFIX,tencent-cloud.net,DC
  - DOMAIN-SUFFIX,tencent.com,DC
  - DOMAIN-SUFFIX,tencentmind.com,DC
  - DOMAIN-SUFFIX,tenpay.com,DC
  - DOMAIN-SUFFIX,wechat.com,DC
  - DOMAIN-SUFFIX,weixin.com,DC
  - DOMAIN-SUFFIX,weiyun.com,DC
  - DOMAIN-SUFFIX,appsimg.com,DC
  - DOMAIN-SUFFIX,appvipshop.com,DC
  - DOMAIN-SUFFIX,vip.com,DC
  - DOMAIN-SUFFIX,vipstatic.com,DC
  - DOMAIN-SUFFIX,ximalaya.com,DC
  - DOMAIN-SUFFIX,xmcdn.com,DC
  - DOMAIN-SUFFIX,00cdn.com,DC
  - DOMAIN-SUFFIX,88cdn.com,DC
  - DOMAIN-SUFFIX,kanimg.com,DC
  - DOMAIN-SUFFIX,kankan.com,DC
  - DOMAIN-SUFFIX,p2cdn.com,DC
  - DOMAIN-SUFFIX,sandai.net,DC
  - DOMAIN-SUFFIX,thundercdn.com,DC
  - DOMAIN-SUFFIX,xunlei.com,DC
  - DOMAIN-SUFFIX,got001.com,DC
  - DOMAIN-SUFFIX,p4pfile.com,DC
  - DOMAIN-SUFFIX,rrys.tv,DC
  - DOMAIN-SUFFIX,rrys2020.com,DC
  - DOMAIN-SUFFIX,yyets.com,DC
  - DOMAIN-SUFFIX,zimuzu.io,DC
  - DOMAIN-SUFFIX,zimuzu.tv,DC
  - DOMAIN-SUFFIX,zmz001.com,DC
  - DOMAIN-SUFFIX,zmz002.com,DC
  - DOMAIN-SUFFIX,zmz003.com,DC
  - DOMAIN-SUFFIX,zmz004.com,DC
  - DOMAIN-SUFFIX,zmz2019.com,DC
  - DOMAIN-SUFFIX,zmzapi.com,DC
  - DOMAIN-SUFFIX,zmzapi.net,DC
  - DOMAIN-SUFFIX,zmzfile.com,DC
  - DOMAIN-SUFFIX,teamviewer.com,DC
  - IP-CIDR,139.220.243.27/32,DC,no-resolve
  - IP-CIDR,172.16.102.56/32,DC,no-resolve
  - IP-CIDR,185.188.32.1/28,DC,no-resolve
  - IP-CIDR,221.226.128.146/32,DC,no-resolve
  - IP-CIDR6,2a0b:b580::/48,DC,no-resolve
  - IP-CIDR6,2a0b:b581::/48,DC,no-resolve
  - IP-CIDR6,2a0b:b582::/48,DC,no-resolve
  - IP-CIDR6,2a0b:b583::/48,DC,no-resolve
  - DOMAIN-SUFFIX,baomitu.com,DC
  - DOMAIN-SUFFIX,bootcss.com,DC
  - DOMAIN-SUFFIX,jiasule.com,DC
  - DOMAIN-SUFFIX,staticfile.org,DC
  - DOMAIN-SUFFIX,upaiyun.com,DC
  - DOMAIN-SUFFIX,doh.pub,DC
  - DOMAIN-SUFFIX,dns.alidns.com,DC
  - DOMAIN-SUFFIX,doh.360.cn,DC
  - IP-CIDR,1.12.12.12/32,DC,no-resolve
  - DOMAIN-SUFFIX,10010.com,DC
  - DOMAIN-SUFFIX,115.com,DC
  - DOMAIN-SUFFIX,12306.com,DC
  - DOMAIN-SUFFIX,17173.com,DC
  - DOMAIN-SUFFIX,178.com,DC
  - DOMAIN-SUFFIX,17k.com,DC
  - DOMAIN-SUFFIX,360doc.com,DC
  - DOMAIN-SUFFIX,36kr.com,DC
  - DOMAIN-SUFFIX,3dmgame.com,DC
  - DOMAIN-SUFFIX,51cto.com,DC
  - DOMAIN-SUFFIX,51job.com,DC
  - DOMAIN-SUFFIX,51jobcdn.com,DC
  - DOMAIN-SUFFIX,56.com,DC
  - DOMAIN-SUFFIX,8686c.com,DC
  - DOMAIN-SUFFIX,abchina.com,DC
  - DOMAIN-SUFFIX,abercrombie.com,DC
  - DOMAIN-SUFFIX,acfun.tv,DC
  - DOMAIN-SUFFIX,air-matters.com,DC
  - DOMAIN-SUFFIX,air-matters.io,DC
  - DOMAIN-SUFFIX,aixifan.com,DC
  - DOMAIN-SUFFIX,algocasts.io,DC
  - DOMAIN-SUFFIX,babytree.com,DC
  - DOMAIN-SUFFIX,babytreeimg.com,DC
  - DOMAIN-SUFFIX,baicizhan.com,DC
  - DOMAIN-SUFFIX,baidupan.com,DC
  - DOMAIN-SUFFIX,baike.com,DC
  - DOMAIN-SUFFIX,biqudu.com,DC
  - DOMAIN-SUFFIX,biquge.com,DC
  - DOMAIN-SUFFIX,bitauto.com,DC
  - DOMAIN-SUFFIX,bosszhipin.com,DC
  - DOMAIN-SUFFIX,c-ctrip.com,DC
  - DOMAIN-SUFFIX,camera360.com,DC
  - DOMAIN-SUFFIX,cdnmama.com,DC
  - DOMAIN-SUFFIX,chaoxing.com,DC
  - DOMAIN-SUFFIX,che168.com,DC
  - DOMAIN-SUFFIX,chinacache.net,DC
  - DOMAIN-SUFFIX,chinaso.com,DC
  - DOMAIN-SUFFIX,chinaz.com,DC
  - DOMAIN-SUFFIX,chinaz.net,DC
  - DOMAIN-SUFFIX,chuimg.com,DC
  - DOMAIN-SUFFIX,cibntv.net,DC
  - DOMAIN-SUFFIX,clouddn.com,DC
  - DOMAIN-SUFFIX,cloudxns.net,DC
  - DOMAIN-SUFFIX,cn163.net,DC
  - DOMAIN-SUFFIX,cnblogs.com,DC
  - DOMAIN-SUFFIX,cnki.net,DC
  - DOMAIN-SUFFIX,cnmstl.net,DC
  - DOMAIN-SUFFIX,coolapk.com,DC
  - DOMAIN-SUFFIX,coolapkmarket.com,DC
  - DOMAIN-SUFFIX,csdn.net,DC
  - DOMAIN-SUFFIX,ctrip.com,DC
  - DOMAIN-SUFFIX,dangdang.com,DC
  - DOMAIN-SUFFIX,dfcfw.com,DC
  - DOMAIN-SUFFIX,dianping.com,DC
  - DOMAIN-SUFFIX,dilidili.wang,DC
  - DOMAIN-SUFFIX,douban.com,DC
  - DOMAIN-SUFFIX,doubanio.com,DC
  - DOMAIN-SUFFIX,dpfile.com,DC
  - DOMAIN-SUFFIX,duowan.com,DC
  - DOMAIN-SUFFIX,dxycdn.com,DC
  - DOMAIN-SUFFIX,dytt8.net,DC
  - DOMAIN-SUFFIX,easou.com,DC
  - DOMAIN-SUFFIX,eastday.com,DC
  - DOMAIN-SUFFIX,eastmoney.com,DC
  - DOMAIN-SUFFIX,ecitic.com,DC
  - DOMAIN-SUFFIX,element-plus.org,DC
  - DOMAIN-SUFFIX,ewqcxz.com,DC
  - DOMAIN-SUFFIX,fang.com,DC
  - DOMAIN-SUFFIX,fantasy.tv,DC
  - DOMAIN-SUFFIX,feng.com,DC
  - DOMAIN-SUFFIX,fengkongcloud.com,DC
  - DOMAIN-SUFFIX,fir.im,DC
  - DOMAIN-SUFFIX,frdic.com,DC
  - DOMAIN-SUFFIX,fresh-ideas.cc,DC
  - DOMAIN-SUFFIX,ganji.com,DC
  - DOMAIN-SUFFIX,ganjistatic1.com,DC
  - DOMAIN-SUFFIX,geetest.com,DC
  - DOMAIN-SUFFIX,geilicdn.com,DC
  - DOMAIN-SUFFIX,ghpym.com,DC
  - DOMAIN-SUFFIX,godic.net,DC
  - DOMAIN-SUFFIX,guazi.com,DC
  - DOMAIN-SUFFIX,gwdang.com,DC
  - DOMAIN-SUFFIX,gzlzfm.com,DC
  - DOMAIN-SUFFIX,haibian.com,DC
  - DOMAIN-SUFFIX,haosou.com,DC
  - DOMAIN-SUFFIX,hollisterco.com,DC
  - DOMAIN-SUFFIX,hongxiu.com,DC
  - DOMAIN-SUFFIX,huajiao.com,DC
  - DOMAIN-SUFFIX,hupu.com,DC
  - DOMAIN-SUFFIX,huxiucdn.com,DC
  - DOMAIN-SUFFIX,huya.com,DC
  - DOMAIN-SUFFIX,ifeng.com,DC
  - DOMAIN-SUFFIX,ifengimg.com,DC
  - DOMAIN-SUFFIX,images-amazon.com,DC
  - DOMAIN-SUFFIX,infzm.com,DC
  - DOMAIN-SUFFIX,ipip.net,DC
  - DOMAIN-SUFFIX,it168.com,DC
  - DOMAIN-SUFFIX,ithome.com,DC
  - DOMAIN-SUFFIX,ixdzs.com,DC
  - DOMAIN-SUFFIX,jianguoyun.com,DC
  - DOMAIN-SUFFIX,jianshu.com,DC
  - DOMAIN-SUFFIX,jianshu.io,DC
  - DOMAIN-SUFFIX,jianshuapi.com,DC
  - DOMAIN-SUFFIX,jiathis.com,DC
  - DOMAIN-SUFFIX,jmstatic.com,DC
  - DOMAIN-SUFFIX,jumei.com,DC
  - DOMAIN-SUFFIX,kaola.com,DC
  - DOMAIN-SUFFIX,knewone.com,DC
  - DOMAIN-SUFFIX,koowo.com,DC
  - DOMAIN-SUFFIX,koyso.com,DC
  - DOMAIN-SUFFIX,ksyungslb.com,DC
  - DOMAIN-SUFFIX,kuaidi100.com,DC
  - DOMAIN-SUFFIX,kugou.com,DC
  - DOMAIN-SUFFIX,lancdns.com,DC
  - DOMAIN-SUFFIX,landiannews.com,DC
  - DOMAIN-SUFFIX,lanzou.com,DC
  - DOMAIN-SUFFIX,lanzoui.com,DC
  - DOMAIN-SUFFIX,lanzoux.com,DC
  - DOMAIN-SUFFIX,lemicp.com,DC
  - DOMAIN-SUFFIX,letitfly.me,DC
  - DOMAIN-SUFFIX,lizhi.fm,DC
  - DOMAIN-SUFFIX,lizhi.io,DC
  - DOMAIN-SUFFIX,lizhifm.com,DC
  - DOMAIN-SUFFIX,luoo.net,DC
  - DOMAIN-SUFFIX,lvmama.com,DC
  - DOMAIN-SUFFIX,lxdns.com,DC
  - DOMAIN-SUFFIX,maoyan.com,DC
  - DOMAIN-SUFFIX,meilishuo.com,DC
  - DOMAIN-SUFFIX,meituan.com,DC
  - DOMAIN-SUFFIX,meituan.net,DC
  - DOMAIN-SUFFIX,meizu.com,DC
  - DOMAIN-SUFFIX,migucloud.com,DC
  - DOMAIN-SUFFIX,miguvideo.com,DC
  - DOMAIN-SUFFIX,mobike.com,DC
  - DOMAIN-SUFFIX,mogu.com,DC
  - DOMAIN-SUFFIX,mogucdn.com,DC
  - DOMAIN-SUFFIX,mogujie.com,DC
  - DOMAIN-SUFFIX,moji.com,DC
  - DOMAIN-SUFFIX,moke.com,DC
  - DOMAIN-SUFFIX,msstatic.com,DC
  - DOMAIN-SUFFIX,mubu.com,DC
  - DOMAIN-SUFFIX,myunlu.com,DC
  - DOMAIN-SUFFIX,nruan.com,DC
  - DOMAIN-SUFFIX,nuomi.com,DC
  - DOMAIN-SUFFIX,onedns.net,DC
  - DOMAIN-SUFFIX,oneplus.com,DC
  - DOMAIN-SUFFIX,onlinedown.net,DC
  - DOMAIN-SUFFIX,oracle.com,DC
  - DOMAIN-SUFFIX,oschina.net,DC
  - DOMAIN-SUFFIX,ourdvs.com,DC
  - DOMAIN-SUFFIX,polyv.net,DC
  - DOMAIN-SUFFIX,qbox.me,DC
  - DOMAIN-SUFFIX,qcloud.com,DC
  - DOMAIN-SUFFIX,qcloudcdn.com,DC
  - DOMAIN-SUFFIX,qdaily.com,DC
  - DOMAIN-SUFFIX,qdmm.com,DC
  - DOMAIN-SUFFIX,qhimg.com,DC
  - DOMAIN-SUFFIX,qianqian.com,DC
  - DOMAIN-SUFFIX,qidian.com,DC
  - DOMAIN-SUFFIX,qihucdn.com,DC
  - DOMAIN-SUFFIX,qin.io,DC
  - DOMAIN-SUFFIX,qiniu.com,DC
  - DOMAIN-SUFFIX,qiniucdn.com,DC
  - DOMAIN-SUFFIX,qiniudn.com,DC
  - DOMAIN-SUFFIX,qiushibaike.com,DC
  - DOMAIN-SUFFIX,quanmin.tv,DC
  - DOMAIN-SUFFIX,qunar.com,DC
  - DOMAIN-SUFFIX,qunarzz.com,DC
  - DOMAIN-SUFFIX,realme.com,DC
  - DOMAIN-SUFFIX,repaik.com,DC
  - DOMAIN-SUFFIX,ruguoapp.com,DC
  - DOMAIN-SUFFIX,runoob.com,DC
  - DOMAIN-SUFFIX,sankuai.com,DC
  - DOMAIN-SUFFIX,segmentfault.com,DC
  - DOMAIN-SUFFIX,sf-express.com,DC
  - DOMAIN-SUFFIX,shumilou.net,DC
  - DOMAIN-SUFFIX,simplecd.me,DC
  - DOMAIN-SUFFIX,smzdm.com,DC
  - DOMAIN-SUFFIX,snwx.com,DC
  - DOMAIN-SUFFIX,soufunimg.com,DC
  - DOMAIN-SUFFIX,sspai.com,DC
  - DOMAIN-SUFFIX,startssl.com,DC
  - DOMAIN-SUFFIX,suning.com,DC
  - DOMAIN-SUFFIX,synology.com,DC
  - DOMAIN-SUFFIX,taihe.com,DC
  - DOMAIN-SUFFIX,th-sjy.com,DC
  - DOMAIN-SUFFIX,tianqi.com,DC
  - DOMAIN-SUFFIX,tianqistatic.com,DC
  - DOMAIN-SUFFIX,tianyancha.com,DC
  - DOMAIN-SUFFIX,tianyaui.com,DC
  - DOMAIN-SUFFIX,tietuku.com,DC
  - DOMAIN-SUFFIX,tiexue.net,DC
  - DOMAIN-SUFFIX,tmiaoo.com,DC
  - DOMAIN-SUFFIX,trip.com,DC
  - DOMAIN-SUFFIX,ttmeiju.com,DC
  - DOMAIN-SUFFIX,tudou.com,DC
  - DOMAIN-SUFFIX,tuniu.com,DC
  - DOMAIN-SUFFIX,tuniucdn.com,DC
  - DOMAIN-SUFFIX,umengcloud.com,DC
  - DOMAIN-SUFFIX,upyun.com,DC
  - DOMAIN-SUFFIX,uxengine.net,DC
  - DOMAIN-SUFFIX,videocc.net,DC
  - DOMAIN-SUFFIX,vivo.com,DC
  - DOMAIN-SUFFIX,wandoujia.com,DC
  - DOMAIN-SUFFIX,weather.com,DC
  - DOMAIN-SUFFIX,weico.cc,DC
  - DOMAIN-SUFFIX,weidian.com,DC
  - DOMAIN-SUFFIX,weiphone.com,DC
  - DOMAIN-SUFFIX,weiphone.net,DC
  - DOMAIN-SUFFIX,womai.com,DC
  - DOMAIN-SUFFIX,wscdns.com,DC
  - DOMAIN-SUFFIX,xdrig.com,DC
  - DOMAIN-SUFFIX,xhscdn.com,DC
  - DOMAIN-SUFFIX,xiachufang.com,DC
  - DOMAIN-SUFFIX,xiaohongshu.com,DC
  - DOMAIN-SUFFIX,xiaojukeji.com,DC
  - DOMAIN-SUFFIX,xinhuanet.com,DC
  - DOMAIN-SUFFIX,xip.io,DC
  - DOMAIN-SUFFIX,xitek.com,DC
  - DOMAIN-SUFFIX,xiumi.us,DC
  - DOMAIN-SUFFIX,xslb.net,DC
  - DOMAIN-SUFFIX,xueqiu.com,DC
  - DOMAIN-SUFFIX,yach.me,DC
  - DOMAIN-SUFFIX,yeepay.com,DC
  - DOMAIN-SUFFIX,yhd.com,DC
  - DOMAIN-SUFFIX,yihaodianimg.com,DC
  - DOMAIN-SUFFIX,yinxiang.com,DC
  - DOMAIN-SUFFIX,yinyuetai.com,DC
  - DOMAIN-SUFFIX,yixia.com,DC
  - DOMAIN-SUFFIX,ys168.com,DC
  - DOMAIN-SUFFIX,yuewen.com,DC
  - DOMAIN-SUFFIX,yy.com,DC
  - DOMAIN-SUFFIX,yystatic.com,DC
  - DOMAIN-SUFFIX,zealer.com,DC
  - DOMAIN-SUFFIX,zhangzishi.cc,DC
  - DOMAIN-SUFFIX,zhanqi.tv,DC
  - DOMAIN-SUFFIX,zhaopin.com,DC
  - DOMAIN-SUFFIX,zhihu.com,DC
  - DOMAIN-SUFFIX,zhimg.com,DC
  - DOMAIN-SUFFIX,zhipin.com,DC
  - DOMAIN-SUFFIX,zhongsou.com,DC
  - DOMAIN-SUFFIX,zhuihd.com,DC
  - IP-CIDR,8.128.0.0/10,DC,no-resolve
  - IP-CIDR,8.208.0.0/12,DC,no-resolve
  - IP-CIDR,14.1.112.0/22,DC,no-resolve
  - IP-CIDR,41.222.240.0/22,DC,no-resolve
  - IP-CIDR,41.223.119.0/24,DC,no-resolve
  - IP-CIDR,43.242.168.0/22,DC,no-resolve
  - IP-CIDR,45.112.212.0/22,DC,no-resolve
  - IP-CIDR,47.52.0.0/16,DC,no-resolve
  - IP-CIDR,47.56.0.0/15,DC,no-resolve
  - IP-CIDR,47.74.0.0/15,DC,no-resolve
  - IP-CIDR,47.76.0.0/14,DC,no-resolve
  - IP-CIDR,47.80.0.0/12,DC,no-resolve
  - IP-CIDR,47.235.0.0/16,DC,no-resolve
  - IP-CIDR,47.236.0.0/14,DC,no-resolve
  - IP-CIDR,47.240.0.0/14,DC,no-resolve
  - IP-CIDR,47.244.0.0/15,DC,no-resolve
  - IP-CIDR,47.246.0.0/16,DC,no-resolve
  - IP-CIDR,47.250.0.0/15,DC,no-resolve
  - IP-CIDR,47.252.0.0/15,DC,no-resolve
  - IP-CIDR,47.254.0.0/16,DC,no-resolve
  - IP-CIDR,59.82.0.0/20,DC,no-resolve
  - IP-CIDR,59.82.240.0/21,DC,no-resolve
  - IP-CIDR,59.82.248.0/22,DC,no-resolve
  - IP-CIDR,72.254.0.0/16,DC,no-resolve
  - IP-CIDR,103.38.56.0/22,DC,no-resolve
  - IP-CIDR,103.52.76.0/22,DC,no-resolve
  - IP-CIDR,103.206.40.0/22,DC,no-resolve
  - IP-CIDR,110.76.21.0/24,DC,no-resolve
  - IP-CIDR,110.76.23.0/24,DC,no-resolve
  - IP-CIDR,112.125.0.0/17,DC,no-resolve
  - IP-CIDR,116.251.64.0/18,DC,no-resolve
  - IP-CIDR,119.38.208.0/20,DC,no-resolve
  - IP-CIDR,119.38.224.0/20,DC,no-resolve
  - IP-CIDR,119.42.224.0/20,DC,no-resolve
  - IP-CIDR,139.95.0.0/16,DC,no-resolve
  - IP-CIDR,140.205.1.0/24,DC,no-resolve
  - IP-CIDR,140.205.122.0/24,DC,no-resolve
  - IP-CIDR,147.139.0.0/16,DC,no-resolve
  - IP-CIDR,149.129.0.0/16,DC,no-resolve
  - IP-CIDR,155.102.0.0/16,DC,no-resolve
  - IP-CIDR,161.117.0.0/16,DC,no-resolve
  - IP-CIDR,163.181.0.0/16,DC,no-resolve
  - IP-CIDR,170.33.0.0/16,DC,no-resolve
  - IP-CIDR,198.11.128.0/18,DC,no-resolve
  - IP-CIDR,205.204.96.0/19,DC,no-resolve
  - IP-CIDR,19.28.0.0/23,DC,no-resolve
  - IP-CIDR,45.40.192.0/19,DC,no-resolve
  - IP-CIDR,49.51.0.0/16,DC,no-resolve
  - IP-CIDR,62.234.0.0/16,DC,no-resolve
  - IP-CIDR,94.191.0.0/17,DC,no-resolve
  - IP-CIDR,103.7.28.0/22,DC,no-resolve
  - IP-CIDR,103.116.50.0/23,DC,no-resolve
  - IP-CIDR,103.231.60.0/24,DC,no-resolve
  - IP-CIDR,109.244.0.0/16,DC,no-resolve
  - IP-CIDR,111.30.128.0/21,DC,no-resolve
  - IP-CIDR,111.30.136.0/24,DC,no-resolve
  - IP-CIDR,111.30.139.0/24,DC,no-resolve
  - IP-CIDR,111.30.140.0/23,DC,no-resolve
  - IP-CIDR,115.159.0.0/16,DC,no-resolve
  - IP-CIDR,119.28.0.0/15,DC,no-resolve
  - IP-CIDR,120.88.56.0/23,DC,no-resolve
  - IP-CIDR,121.51.0.0/16,DC,no-resolve
  - IP-CIDR,129.28.0.0/16,DC,no-resolve
  - IP-CIDR,129.204.0.0/16,DC,no-resolve
  - IP-CIDR,129.211.0.0/16,DC,no-resolve
  - IP-CIDR,132.232.0.0/16,DC,no-resolve
  - IP-CIDR,134.175.0.0/16,DC,no-resolve
  - IP-CIDR,146.56.192.0/18,DC,no-resolve
  - IP-CIDR,148.70.0.0/16,DC,no-resolve
  - IP-CIDR,150.109.0.0/16,DC,no-resolve
  - IP-CIDR,152.136.0.0/16,DC,no-resolve
  - IP-CIDR,162.14.0.0/16,DC,no-resolve
  - IP-CIDR,162.62.0.0/16,DC,no-resolve
  - IP-CIDR,170.106.130.0/24,DC,no-resolve
  - IP-CIDR,182.254.0.0/16,DC,no-resolve
  - IP-CIDR,188.131.128.0/17,DC,no-resolve
  - IP-CIDR,203.195.128.0/17,DC,no-resolve
  - IP-CIDR,203.205.128.0/17,DC,no-resolve
  - IP-CIDR,210.4.138.0/24,DC,no-resolve
  - IP-CIDR,211.152.128.0/23,DC,no-resolve
  - IP-CIDR,211.152.132.0/23,DC,no-resolve
  - IP-CIDR,211.152.148.0/23,DC,no-resolve
  - IP-CIDR,212.64.0.0/17,DC,no-resolve
  - IP-CIDR,212.129.128.0/17,DC,no-resolve
  - IP-CIDR,45.113.192.0/22,DC,no-resolve
  - IP-CIDR,63.217.23.0/24,DC,no-resolve
  - IP-CIDR,63.243.252.0/24,DC,no-resolve
  - IP-CIDR,103.235.44.0/22,DC,no-resolve
  - IP-CIDR,104.193.88.0/22,DC,no-resolve
  - IP-CIDR,106.12.0.0/15,DC,no-resolve
  - IP-CIDR,114.28.224.0/20,DC,no-resolve
  - IP-CIDR,119.63.192.0/21,DC,no-resolve
  - IP-CIDR,180.76.0.0/24,DC,no-resolve
  - IP-CIDR,180.76.0.0/16,DC,no-resolve
  - IP-CIDR,182.61.0.0/16,DC,no-resolve
  - IP-CIDR,185.10.104.0/22,DC,no-resolve
  - IP-CIDR,202.46.48.0/20,DC,no-resolve
  - IP-CIDR,203.90.238.0/24,DC,no-resolve
  - IP-CIDR,43.254.0.0/22,DC,no-resolve
  - IP-CIDR,45.249.212.0/22,DC,no-resolve
  - IP-CIDR,49.4.0.0/17,DC,no-resolve
  - IP-CIDR,78.101.192.0/19,DC,no-resolve
  - IP-CIDR,78.101.224.0/20,DC,no-resolve
  - IP-CIDR,81.52.161.0/24,DC,no-resolve
  - IP-CIDR,85.97.220.0/22,DC,no-resolve
  - IP-CIDR,103.31.200.0/22,DC,no-resolve
  - IP-CIDR,103.69.140.0/23,DC,no-resolve
  - IP-CIDR,103.218.216.0/22,DC,no-resolve
  - IP-CIDR,114.115.128.0/17,DC,no-resolve
  - IP-CIDR,114.116.0.0/16,DC,no-resolve
  - IP-CIDR,116.63.128.0/18,DC,no-resolve
  - IP-CIDR,116.66.184.0/22,DC,no-resolve
  - IP-CIDR,116.71.96.0/20,DC,no-resolve
  - IP-CIDR,116.71.128.0/21,DC,no-resolve
  - IP-CIDR,116.71.136.0/22,DC,no-resolve
  - IP-CIDR,116.71.141.0/24,DC,no-resolve
  - IP-CIDR,116.71.142.0/24,DC,no-resolve
  - IP-CIDR,116.71.243.0/24,DC,no-resolve
  - IP-CIDR,116.71.244.0/24,DC,no-resolve
  - IP-CIDR,116.71.251.0/24,DC,no-resolve
  - IP-CIDR,117.78.0.0/18,DC,no-resolve
  - IP-CIDR,119.3.0.0/16,DC,no-resolve
  - IP-CIDR,119.8.0.0/21,DC,no-resolve
  - IP-CIDR,119.8.32.0/19,DC,no-resolve
  - IP-CIDR,121.36.0.0/17,DC,no-resolve
  - IP-CIDR,121.36.128.0/18,DC,no-resolve
  - IP-CIDR,121.37.0.0/17,DC,no-resolve
  - IP-CIDR,122.112.128.0/17,DC,no-resolve
  - IP-CIDR,139.9.0.0/18,DC,no-resolve
  - IP-CIDR,139.9.64.0/19,DC,no-resolve
  - IP-CIDR,139.9.100.0/22,DC,no-resolve
  - IP-CIDR,139.9.104.0/21,DC,no-resolve
  - IP-CIDR,139.9.112.0/20,DC,no-resolve
  - IP-CIDR,139.9.128.0/18,DC,no-resolve
  - IP-CIDR,139.9.192.0/19,DC,no-resolve
  - IP-CIDR,139.9.224.0/20,DC,no-resolve
  - IP-CIDR,139.9.240.0/21,DC,no-resolve
  - IP-CIDR,139.9.248.0/22,DC,no-resolve
  - IP-CIDR,139.159.128.0/19,DC,no-resolve
  - IP-CIDR,139.159.160.0/22,DC,no-resolve
  - IP-CIDR,139.159.164.0/23,DC,no-resolve
  - IP-CIDR,139.159.168.0/21,DC,no-resolve
  - IP-CIDR,139.159.176.0/20,DC,no-resolve
  - IP-CIDR,139.159.192.0/18,DC,no-resolve
  - IP-CIDR,159.138.0.0/18,DC,no-resolve
  - IP-CIDR,159.138.64.0/21,DC,no-resolve
  - IP-CIDR,159.138.79.0/24,DC,no-resolve
  - IP-CIDR,159.138.80.0/20,DC,no-resolve
  - IP-CIDR,159.138.96.0/20,DC,no-resolve
  - IP-CIDR,159.138.112.0/21,DC,no-resolve
  - IP-CIDR,159.138.125.0/24,DC,no-resolve
  - IP-CIDR,159.138.128.0/18,DC,no-resolve
  - IP-CIDR,159.138.192.0/20,DC,no-resolve
  - IP-CIDR,159.138.223.0/24,DC,no-resolve
  - IP-CIDR,159.138.224.0/19,DC,no-resolve
  - IP-CIDR,168.195.92.0/22,DC,no-resolve
  - IP-CIDR,185.176.76.0/22,DC,no-resolve
  - IP-CIDR,197.199.0.0/18,DC,no-resolve
  - IP-CIDR,197.210.163.0/24,DC,no-resolve
  - IP-CIDR,197.252.1.0/24,DC,no-resolve
  - IP-CIDR,197.252.2.0/23,DC,no-resolve
  - IP-CIDR,197.252.4.0/22,DC,no-resolve
  - IP-CIDR,197.252.8.0/21,DC,no-resolve
  - IP-CIDR,200.32.52.0/24,DC,no-resolve
  - IP-CIDR,200.32.54.0/24,DC,no-resolve
  - IP-CIDR,200.32.57.0/24,DC,no-resolve
  - IP-CIDR,203.135.0.0/22,DC,no-resolve
  - IP-CIDR,203.135.4.0/23,DC,no-resolve
  - IP-CIDR,203.135.8.0/23,DC,no-resolve
  - IP-CIDR,203.135.11.0/24,DC,no-resolve
  - IP-CIDR,203.135.13.0/24,DC,no-resolve
  - IP-CIDR,203.135.20.0/24,DC,no-resolve
  - IP-CIDR,203.135.22.0/23,DC,no-resolve
  - IP-CIDR,203.135.24.0/23,DC,no-resolve
  - IP-CIDR,203.135.26.0/24,DC,no-resolve
  - IP-CIDR,203.135.29.0/24,DC,no-resolve
  - IP-CIDR,203.135.33.0/24,DC,no-resolve
  - IP-CIDR,203.135.38.0/23,DC,no-resolve
  - IP-CIDR,203.135.40.0/24,DC,no-resolve
  - IP-CIDR,203.135.43.0/24,DC,no-resolve
  - IP-CIDR,203.135.48.0/24,DC,no-resolve
  - IP-CIDR,203.135.50.0/24,DC,no-resolve
  - IP-CIDR,42.186.0.0/16,DC,no-resolve
  - IP-CIDR,45.127.128.0/22,DC,no-resolve
  - IP-CIDR,45.195.24.0/24,DC,no-resolve
  - IP-CIDR,45.253.132.0/22,DC,no-resolve
  - IP-CIDR,45.253.240.0/22,DC,no-resolve
  - IP-CIDR,45.254.48.0/23,DC,no-resolve
  - IP-CIDR,59.111.0.0/20,DC,no-resolve
  - IP-CIDR,59.111.128.0/17,DC,no-resolve
  - IP-CIDR,103.71.120.0/21,DC,no-resolve
  - IP-CIDR,103.71.128.0/22,DC,no-resolve
  - IP-CIDR,103.71.196.0/22,DC,no-resolve
  - IP-CIDR,103.71.200.0/22,DC,no-resolve
  - IP-CIDR,103.72.12.0/22,DC,no-resolve
  - IP-CIDR,103.72.18.0/23,DC,no-resolve
  - IP-CIDR,103.72.24.0/22,DC,no-resolve
  - IP-CIDR,103.72.28.0/23,DC,no-resolve
  - IP-CIDR,103.72.38.0/23,DC,no-resolve
  - IP-CIDR,103.72.40.0/23,DC,no-resolve
  - IP-CIDR,103.72.44.0/22,DC,no-resolve
  - IP-CIDR,103.72.48.0/21,DC,no-resolve
  - IP-CIDR,103.72.128.0/21,DC,no-resolve
  - IP-CIDR,103.74.24.0/21,DC,no-resolve
  - IP-CIDR,103.74.48.0/22,DC,no-resolve
  - IP-CIDR,103.126.92.0/22,DC,no-resolve
  - IP-CIDR,103.129.252.0/22,DC,no-resolve
  - IP-CIDR,103.131.252.0/22,DC,no-resolve
  - IP-CIDR,103.135.240.0/22,DC,no-resolve
  - IP-CIDR,103.196.64.0/22,DC,no-resolve
  - IP-CIDR,106.2.32.0/19,DC,no-resolve
  - IP-CIDR,106.2.64.0/18,DC,no-resolve
  - IP-CIDR,114.113.196.0/22,DC,no-resolve
  - IP-CIDR,114.113.200.0/22,DC,no-resolve
  - IP-CIDR,115.236.112.0/20,DC,no-resolve
  - IP-CIDR,115.238.76.0/22,DC,no-resolve
  - IP-CIDR,123.58.160.0/19,DC,no-resolve
  - IP-CIDR,223.252.192.0/19,DC,no-resolve
  - IP-CIDR,101.198.128.0/18,DC,no-resolve
  - IP-CIDR,101.198.192.0/19,DC,no-resolve
  - IP-CIDR,101.199.196.0/22,DC,no-resolve
  - PROCESS-NAME,aria2c.exe,DC
  - PROCESS-NAME,fdm.exe,DC
  - PROCESS-NAME,Folx.exe,DC
  - PROCESS-NAME,NetTransport.exe,DC
  - PROCESS-NAME,Thunder.exe,DC
  - PROCESS-NAME,Transmission.exe,DC
  - PROCESS-NAME,uTorrent.exe,DC
  - PROCESS-NAME,WebTorrent.exe,DC
  - PROCESS-NAME,WebTorrent Helper.exe,DC
  - PROCESS-NAME,qbittorrent.exe,DC
  - DOMAIN-SUFFIX,smtp,DC
  - DOMAIN-KEYWORD,aria2,DC
  - PROCESS-NAME,DownloadService.exe,DC
  - PROCESS-NAME,Weiyun.exe,DC
  - PROCESS-NAME,baidunetdisk.exe,DC
  - DOMAIN,ic.adobe.io,AD-BAN
  - DOMAIN,cc-api-data.adobe.io,AD-BAN
  - DOMAIN,cc-api-data-stage.adobe.io,AD-BAN
  - DOMAIN,prod.adobegenuine.com,AD-BAN
  - DOMAIN,gocart-web-prod-ue1-alb-1461435473.us-east-1.elb.amazonaws.com,AD-BAN
  - DOMAIN,0mo5a70cqa.adobe.io,AD-BAN
  - DOMAIN,1b9khekel6.adobe.io,AD-BAN
  - DOMAIN,1hzopx6nz7.adobe.io,AD-BAN
  - DOMAIN,22gda3bxkb.adobe.io,AD-BAN
  - DOMAIN,23ynjitwt5.adobe.io,AD-BAN
  - DOMAIN,2ftem87osk.adobe.io,AD-BAN
  - DOMAIN,3ca52znvmj.adobe.io,AD-BAN
  - DOMAIN,3d3wqt96ht.adobe.io,AD-BAN
  - DOMAIN,4vzokhpsbs.adobe.io,AD-BAN
  - DOMAIN,5zgzzv92gn.adobe.io,AD-BAN
  - DOMAIN,69tu0xswvq.adobe.io,AD-BAN
  - DOMAIN,7g2gzgk9g1.adobe.io,AD-BAN
  - DOMAIN,7m31guub0q.adobe.io,AD-BAN
  - DOMAIN,7sj9n87sls.adobe.io,AD-BAN
  - DOMAIN,8ncdzpmmrg.adobe.io,AD-BAN
  - DOMAIN,9ngulmtgqi.adobe.io,AD-BAN
  - DOMAIN,aoorovjtha.adobe.io,AD-BAN
  - DOMAIN,b5kbg2ggog.adobe.io,AD-BAN
  - DOMAIN,cd536oo20y.adobe.io,AD-BAN
  - DOMAIN,dxyeyf6ecy.adobe.io,AD-BAN
  - DOMAIN,dyzt55url8.adobe.io,AD-BAN
  - DOMAIN,fgh5v09kcn.adobe.io,AD-BAN
  - DOMAIN,fqaq3pq1o9.adobe.io,AD-BAN
  - DOMAIN,guzg78logz.adobe.io,AD-BAN
  - DOMAIN,gw8gfjbs05.adobe.io,AD-BAN
  - DOMAIN,i7pq6fgbsl.adobe.io,AD-BAN
  - DOMAIN,ij0gdyrfka.adobe.io,AD-BAN
  - DOMAIN,ivbnpthtl2.adobe.io,AD-BAN
  - DOMAIN,jc95y2v12r.adobe.io,AD-BAN
  - DOMAIN,lre1kgz2u4.adobe.io,AD-BAN
  - DOMAIN,m59b4msyph.adobe.io,AD-BAN
  - DOMAIN,p0bjuoe16a.adobe.io,AD-BAN
  - DOMAIN,p7uxzbht8h.adobe.io,AD-BAN
  - DOMAIN,ph0f2h2csf.adobe.io,AD-BAN
  - DOMAIN,pojvrj7ho5.adobe.io,AD-BAN
  - DOMAIN,r3zj0yju1q.adobe.io,AD-BAN
  - DOMAIN,r5hacgq5w6.adobe.io,AD-BAN
  - DOMAIN,vajcbj9qgq.adobe.io,AD-BAN
  - DOMAIN,vcorzsld2a.adobe.io,AD-BAN
  - DOMAIN,7hewqka7ix.adobe.io,AD-BAN
  - DOMAIN,4hvtkfouhu.adobe.io,AD-BAN
  - DOMAIN,bo3u7sbfvf.adobe.io,AD-BAN
  - DOMAIN,h9m2j0ykj7.adobe.io,AD-BAN
  - DOMAIN,8n1u6aggep.adobe.io,AD-BAN
  - DOMAIN,ej4o5b9gac.adobe.io,AD-BAN
  - DOMAIN,hu0em4wmio.adobe.io,AD-BAN
  - DOMAIN,q2ge7bxibl.adobe.io,AD-BAN
  - DOMAIN,zh9yrmh2lu.adobe.io,AD-BAN
  - DOMAIN,cv218qmzox6.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv24b15c1z0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv24v41zibm.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv256ds6c99.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2b0yc07ls.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2bqhsp36w.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2fcqvzl1r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2l4573ukh.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2nn9r0j2r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2ska86hnt.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2ys4tjt9x.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2yt8sqmh0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2zp87w2eo.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv218qmzox6.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv24b15c1z0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv24v41zibm.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv256ds6c99.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2b0yc07ls.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2bqhsp36w.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2fcqvzl1r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2l4573ukh.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2nn9r0j2r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2ska86hnt.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2ys4tjt9x.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2yt8sqmh0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2zp87w2eo.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv218qmzox6.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv24b15c1z0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv24v41zibm.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv256ds6c99.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2b0yc07ls.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2bqhsp36w.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2fcqvzl1r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2l4573ukh.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2nn9r0j2r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2ska86hnt.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2ys4tjt9x.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2yt8sqmh0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2zp87w2eo.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,0bj2epfqn1.adobestats.io,AD-BAN
  - DOMAIN,0n8wirm0nv.adobestats.io,AD-BAN
  - DOMAIN,124hzdrtoi.adobestats.io,AD-BAN
  - DOMAIN,17ov1u3gio.adobestats.io,AD-BAN
  - DOMAIN,17vpu0xkm6.adobestats.io,AD-BAN
  - DOMAIN,1ei1f4k9yk.adobestats.io,AD-BAN
  - DOMAIN,1ngcws40i2.adobestats.io,AD-BAN
  - DOMAIN,1qwiekvkux.adobestats.io,AD-BAN
  - DOMAIN,1tw2l9x7xb.adobestats.io,AD-BAN
  - DOMAIN,1unk1rv07w.adobestats.io,AD-BAN
  - DOMAIN,1xuyy0mk2p.adobestats.io,AD-BAN
  - DOMAIN,220zxtbjjl.adobestats.io,AD-BAN
  - DOMAIN,2621x1nzeq.adobestats.io,AD-BAN
  - DOMAIN,28t4psttw7.adobestats.io,AD-BAN
  - DOMAIN,2dhh9vsp39.adobestats.io,AD-BAN
  - DOMAIN,2eiuxr4ky7.adobestats.io,AD-BAN
  - DOMAIN,2o3c6rbyfr.adobestats.io,AD-BAN
  - DOMAIN,2qj10f8rdg.adobestats.io,AD-BAN
  - DOMAIN,2qjz50z5lf.adobestats.io,AD-BAN
  - DOMAIN,31q40256l4.adobestats.io,AD-BAN
  - DOMAIN,34modi5s5d.adobestats.io,AD-BAN
  - DOMAIN,34u96h6rvn.adobestats.io,AD-BAN
  - DOMAIN,3aqshzqv3w.adobestats.io,AD-BAN
  - DOMAIN,3jq65qgxeh.adobestats.io,AD-BAN
  - DOMAIN,3odrrlydxt.adobestats.io,AD-BAN
  - DOMAIN,3u6k9as4bj.adobestats.io,AD-BAN
  - DOMAIN,3uyby7kphu.adobestats.io,AD-BAN
  - DOMAIN,3xuuprv9lg.adobestats.io,AD-BAN
  - DOMAIN,41yq116gxd.adobestats.io,AD-BAN
  - DOMAIN,44qnmxgtif.adobestats.io,AD-BAN
  - DOMAIN,4dviy9tb3o.adobestats.io,AD-BAN
  - DOMAIN,4fmzz4au8r.adobestats.io,AD-BAN
  - DOMAIN,4l6gggpz15.adobestats.io,AD-BAN
  - DOMAIN,4yw5exucf6.adobestats.io,AD-BAN
  - DOMAIN,50sxgwgngu.adobestats.io,AD-BAN
  - DOMAIN,54cu4v5twu.adobestats.io,AD-BAN
  - DOMAIN,561r5c3bz1.adobestats.io,AD-BAN
  - DOMAIN,5ky0dijg73.adobestats.io,AD-BAN
  - DOMAIN,5m62o8ud26.adobestats.io,AD-BAN
  - DOMAIN,5pawwgngcc.adobestats.io,AD-BAN
  - DOMAIN,5zcrcdpvlp.adobestats.io,AD-BAN
  - DOMAIN,69rxfbohle.adobestats.io,AD-BAN
  - DOMAIN,6dnh2pnz6e.adobestats.io,AD-BAN
  - DOMAIN,6eidhihhci.adobestats.io,AD-BAN
  - DOMAIN,6j0onv1tde.adobestats.io,AD-BAN
  - DOMAIN,6mmsqon7y7.adobestats.io,AD-BAN
  - DOMAIN,6purj8tuwe.adobestats.io,AD-BAN
  - DOMAIN,6qkk0k4e9n.adobestats.io,AD-BAN
  - DOMAIN,6t38sdao5e.adobestats.io,AD-BAN
  - DOMAIN,6y6ozj4sot.adobestats.io,AD-BAN
  - DOMAIN,6zknqfiyev.adobestats.io,AD-BAN
  - DOMAIN,79j7psfqg5.adobestats.io,AD-BAN
  - DOMAIN,7k1t5im229.adobestats.io,AD-BAN
  - DOMAIN,7l4xxjhvkt.adobestats.io,AD-BAN
  - DOMAIN,7tu619a87v.adobestats.io,AD-BAN
  - DOMAIN,83x20gw5jk.adobestats.io,AD-BAN
  - DOMAIN,85n85uoa1h.adobestats.io,AD-BAN
  - DOMAIN,8tegcsplp5.adobestats.io,AD-BAN
  - DOMAIN,98c6c096dd.adobestats.io,AD-BAN
  - DOMAIN,98yu7gk4m3.adobestats.io,AD-BAN
  - DOMAIN,99pfl4vazm.adobestats.io,AD-BAN
  - DOMAIN,9g12qgnfe4.adobestats.io,AD-BAN
  - DOMAIN,9iay914wzy.adobestats.io,AD-BAN
  - DOMAIN,9orhsmzhzs.adobestats.io,AD-BAN
  - DOMAIN,9uffo0j6wj.adobestats.io,AD-BAN
  - DOMAIN,9wm8di7ifk.adobestats.io,AD-BAN
  - DOMAIN,a1y2b7wsna.adobestats.io,AD-BAN
  - DOMAIN,a3cgga0v52.adobestats.io,AD-BAN
  - DOMAIN,a9ctb1jmbv.adobestats.io,AD-BAN
  - DOMAIN,ag0ak456at.adobestats.io,AD-BAN
  - DOMAIN,agxqobl83f.adobestats.io,AD-BAN
  - DOMAIN,ah5otkl8ie.adobestats.io,AD-BAN
  - DOMAIN,altz51db7t.adobestats.io,AD-BAN
  - DOMAIN,anl33sxvkb.adobestats.io,AD-BAN
  - DOMAIN,bbraowhh29.adobestats.io,AD-BAN
  - DOMAIN,bjooauydoa.adobestats.io,AD-BAN
  - DOMAIN,bk7y1gneyk.adobestats.io,AD-BAN
  - DOMAIN,bk8pzmo8g4.adobestats.io,AD-BAN
  - DOMAIN,bpvcty7ry7.adobestats.io,AD-BAN
  - DOMAIN,bs2yhuojzm.adobestats.io,AD-BAN
  - DOMAIN,c474kdh1ky.adobestats.io,AD-BAN
  - DOMAIN,c4dpyxapo7.adobestats.io,AD-BAN
  - DOMAIN,cde0alxs25.adobestats.io,AD-BAN
  - DOMAIN,cr2fouxnpm.adobestats.io,AD-BAN
  - DOMAIN,curbpindd3.adobestats.io,AD-BAN
  - DOMAIN,d101mw99xq.adobestats.io,AD-BAN
  - DOMAIN,d2ke1291mx.adobestats.io,AD-BAN
  - DOMAIN,d6zco8is6l.adobestats.io,AD-BAN
  - DOMAIN,dfnm3epsb7.adobestats.io,AD-BAN
  - DOMAIN,dru0w44scl.adobestats.io,AD-BAN
  - DOMAIN,dsj4bsmk6i.adobestats.io,AD-BAN
  - DOMAIN,dx0nvmv4hz.adobestats.io,AD-BAN
  - DOMAIN,dymfhyu5t7.adobestats.io,AD-BAN
  - DOMAIN,dyv9axahup.adobestats.io,AD-BAN
  - DOMAIN,ebvf40engd.adobestats.io,AD-BAN
  - DOMAIN,eftcpaiu36.adobestats.io,AD-BAN
  - DOMAIN,eq7dbze88m.adobestats.io,AD-BAN
  - DOMAIN,eqo0sr8daw.adobestats.io,AD-BAN
  - DOMAIN,esx6aswt5e.adobestats.io,AD-BAN
  - DOMAIN,eu927m40hm.adobestats.io,AD-BAN
  - DOMAIN,eyiu19jd5w.adobestats.io,AD-BAN
  - DOMAIN,ffirm4ruur.adobestats.io,AD-BAN
  - DOMAIN,ffs3xik41x.adobestats.io,AD-BAN
  - DOMAIN,fm8m3wxufy.adobestats.io,AD-BAN
  - DOMAIN,fw6x2fs3fr.adobestats.io,AD-BAN
  - DOMAIN,g0rhyhkd7l.adobestats.io,AD-BAN
  - DOMAIN,g3y09mbaam.adobestats.io,AD-BAN
  - DOMAIN,g9cli80sqp.adobestats.io,AD-BAN
  - DOMAIN,gwbpood8w4.adobestats.io,AD-BAN
  - DOMAIN,hf6s5jdv95.adobestats.io,AD-BAN
  - DOMAIN,hijfpxclgz.adobestats.io,AD-BAN
  - DOMAIN,hjs70w1pdi.adobestats.io,AD-BAN
  - DOMAIN,hmonvr006v.adobestats.io,AD-BAN
  - DOMAIN,hnk7phkxtg.adobestats.io,AD-BAN
  - DOMAIN,hq0mnwz735.adobestats.io,AD-BAN
  - DOMAIN,hwfqhlenbg.adobestats.io,AD-BAN
  - DOMAIN,i2x2ius9o5.adobestats.io,AD-BAN
  - DOMAIN,i4x0voa7ns.adobestats.io,AD-BAN
  - DOMAIN,i6gl29bvy6.adobestats.io,AD-BAN
  - DOMAIN,ijl01wuoed.adobestats.io,AD-BAN
  - DOMAIN,iw4sp0v9h3.adobestats.io,AD-BAN
  - DOMAIN,izke0wrq9n.adobestats.io,AD-BAN
  - DOMAIN,j0qztjp9ep.adobestats.io,AD-BAN
  - DOMAIN,j134yk6hv5.adobestats.io,AD-BAN
  - DOMAIN,j14y4uzge7.adobestats.io,AD-BAN
  - DOMAIN,j5vsm79i8a.adobestats.io,AD-BAN
  - DOMAIN,jaircqa037.adobestats.io,AD-BAN
  - DOMAIN,jatil41mhk.adobestats.io,AD-BAN
  - DOMAIN,je5ufnklzs.adobestats.io,AD-BAN
  - DOMAIN,jfb7fqf90c.adobestats.io,AD-BAN
  - DOMAIN,jir97hss11.adobestats.io,AD-BAN
  - DOMAIN,jmx50quqz0.adobestats.io,AD-BAN
  - DOMAIN,jsspeczo2f.adobestats.io,AD-BAN
  - DOMAIN,jsxfc5yij1.adobestats.io,AD-BAN
  - DOMAIN,jwonv590qs.adobestats.io,AD-BAN
  - DOMAIN,jye4987hyr.adobestats.io,AD-BAN
  - DOMAIN,k9cyzt2wha.adobestats.io,AD-BAN
  - DOMAIN,kbdgy1yszf.adobestats.io,AD-BAN
  - DOMAIN,kgj0gsg3cf.adobestats.io,AD-BAN
  - DOMAIN,kjhzwuhcel.adobestats.io,AD-BAN
  - DOMAIN,klw4np5a1x.adobestats.io,AD-BAN
  - DOMAIN,kvi8uopy6f.adobestats.io,AD-BAN
  - DOMAIN,kvn19sesfx.adobestats.io,AD-BAN
  - DOMAIN,kwi5n2ruax.adobestats.io,AD-BAN
  - DOMAIN,l558s6jwzy.adobestats.io,AD-BAN
  - DOMAIN,ll8xjr580v.adobestats.io,AD-BAN
  - DOMAIN,llnh72p5m3.adobestats.io,AD-BAN
  - DOMAIN,lnwbupw1s7.adobestats.io,AD-BAN
  - DOMAIN,ltjlscpozx.adobestats.io,AD-BAN
  - DOMAIN,lv5yrjxh6i.adobestats.io,AD-BAN
  - DOMAIN,lz2x4rks1u.adobestats.io,AD-BAN
  - DOMAIN,m59cps6x3n.adobestats.io,AD-BAN
  - DOMAIN,m95pt874uw.adobestats.io,AD-BAN
  - DOMAIN,mge8tcrsbr.adobestats.io,AD-BAN
  - DOMAIN,mid2473ggd.adobestats.io,AD-BAN
  - DOMAIN,mme5z7vvqy.adobestats.io,AD-BAN
  - DOMAIN,mpsige2va9.adobestats.io,AD-BAN
  - DOMAIN,n0yaid7q47.adobestats.io,AD-BAN
  - DOMAIN,n17cast4au.adobestats.io,AD-BAN
  - DOMAIN,n746qg9j4i.adobestats.io,AD-BAN
  - DOMAIN,n78vmdxqwc.adobestats.io,AD-BAN
  - DOMAIN,nh8wam2qd9.adobestats.io,AD-BAN
  - DOMAIN,nhc73ypmli.adobestats.io,AD-BAN
  - DOMAIN,nhs5jfxg10.adobestats.io,AD-BAN
  - DOMAIN,no95ceu36c.adobestats.io,AD-BAN
  - DOMAIN,o1qtkpin3e.adobestats.io,AD-BAN
  - DOMAIN,oee5i55vyo.adobestats.io,AD-BAN
  - DOMAIN,oh41yzugiz.adobestats.io,AD-BAN
  - DOMAIN,ok9sn4bf8f.adobestats.io,AD-BAN
  - DOMAIN,om2h3oklke.adobestats.io,AD-BAN
  - DOMAIN,oxiz2n3i4v.adobestats.io,AD-BAN
  - DOMAIN,p3lj3o9h1s.adobestats.io,AD-BAN
  - DOMAIN,p3m760solq.adobestats.io,AD-BAN
  - DOMAIN,p50zgina3e.adobestats.io,AD-BAN
  - DOMAIN,pc6sk9bygv.adobestats.io,AD-BAN
  - DOMAIN,pdb7v5ul5q.adobestats.io,AD-BAN
  - DOMAIN,pf80yxt5md.adobestats.io,AD-BAN
  - DOMAIN,pljm140ld1.adobestats.io,AD-BAN
  - DOMAIN,ppn4fq68w7.adobestats.io,AD-BAN
  - DOMAIN,psc20x5pmv.adobestats.io,AD-BAN
  - DOMAIN,px8vklwioh.adobestats.io,AD-BAN
  - DOMAIN,q9hjwppxeq.adobestats.io,AD-BAN
  - DOMAIN,qmyqpp3xs3.adobestats.io,AD-BAN
  - DOMAIN,qn2ex1zblg.adobestats.io,AD-BAN
  - DOMAIN,qp5bivnlrp.adobestats.io,AD-BAN
  - DOMAIN,qqyyhr3eqr.adobestats.io,AD-BAN
  - DOMAIN,qttaz1hur3.adobestats.io,AD-BAN
  - DOMAIN,qxc5z5sqkv.adobestats.io,AD-BAN
  - DOMAIN,r1lqxul5sr.adobestats.io,AD-BAN
  - DOMAIN,r9r6oomgms.adobestats.io,AD-BAN
  - DOMAIN,rb0u8l34kr.adobestats.io,AD-BAN
  - DOMAIN,riiohpqnpf.adobestats.io,AD-BAN
  - DOMAIN,rj669kv2lc.adobestats.io,AD-BAN
  - DOMAIN,rlo1n6mv52.adobestats.io,AD-BAN
  - DOMAIN,rm3xrk61n1.adobestats.io,AD-BAN
  - DOMAIN,rmnia8d0tr.adobestats.io,AD-BAN
  - DOMAIN,s7odt342lo.adobestats.io,AD-BAN
  - DOMAIN,sa4visje3j.adobestats.io,AD-BAN
  - DOMAIN,sbzo5r4687.adobestats.io,AD-BAN
  - DOMAIN,sfmzkcuf2f.adobestats.io,AD-BAN
  - DOMAIN,skg7pqn0al.adobestats.io,AD-BAN
  - DOMAIN,t9phy8ywkd.adobestats.io,AD-BAN
  - DOMAIN,tcxqcguhww.adobestats.io,AD-BAN
  - DOMAIN,tf3an24xls.adobestats.io,AD-BAN
  - DOMAIN,tprqy2lgua.adobestats.io,AD-BAN
  - DOMAIN,trc2fpy0j4.adobestats.io,AD-BAN
  - DOMAIN,tyradj47rp.adobestats.io,AD-BAN
  - DOMAIN,u31z50xvp9.adobestats.io,AD-BAN
  - DOMAIN,ua0pnr1x8v.adobestats.io,AD-BAN
  - DOMAIN,uf0onoepoe.adobestats.io,AD-BAN
  - DOMAIN,ujqx8lhpz4.adobestats.io,AD-BAN
  - DOMAIN,uo6uihbs9y.adobestats.io,AD-BAN
  - DOMAIN,uqshzexj7y.adobestats.io,AD-BAN
  - DOMAIN,ura7zj55r9.adobestats.io,AD-BAN
  - DOMAIN,uroc9kxpcb.adobestats.io,AD-BAN
  - DOMAIN,uytor2bsee.adobestats.io,AD-BAN
  - DOMAIN,v5nweiv7nf.adobestats.io,AD-BAN
  - DOMAIN,vfsjlgw02v.adobestats.io,AD-BAN
  - DOMAIN,vicsj37lhf.adobestats.io,AD-BAN
  - DOMAIN,vp7ih9xoxg.adobestats.io,AD-BAN
  - DOMAIN,vqiktmz3k1.adobestats.io,AD-BAN
  - DOMAIN,vqrc5mq1tm.adobestats.io,AD-BAN
  - DOMAIN,vr1i32txj7.adobestats.io,AD-BAN
  - DOMAIN,vr25z2lfqx.adobestats.io,AD-BAN
  - DOMAIN,vrz9w7o7yv.adobestats.io,AD-BAN
  - DOMAIN,vvzbv1ba9r.adobestats.io,AD-BAN
  - DOMAIN,w8x0780324.adobestats.io,AD-BAN
  - DOMAIN,wcxqmuxd4z.adobestats.io,AD-BAN
  - DOMAIN,wjoxlf5x2z.adobestats.io,AD-BAN
  - DOMAIN,wtooadkup9.adobestats.io,AD-BAN
  - DOMAIN,wz8kjkd9gc.adobestats.io,AD-BAN
  - DOMAIN,x5cupsunjc.adobestats.io,AD-BAN
  - DOMAIN,x880ulw3h0.adobestats.io,AD-BAN
  - DOMAIN,x8kb03c0jr.adobestats.io,AD-BAN
  - DOMAIN,x8thl73e7u.adobestats.io,AD-BAN
  - DOMAIN,xbd20b9wqa.adobestats.io,AD-BAN
  - DOMAIN,xesnl0ss94.adobestats.io,AD-BAN
  - DOMAIN,xm8abqacqz.adobestats.io,AD-BAN
  - DOMAIN,xqh2khegrf.adobestats.io,AD-BAN
  - DOMAIN,y2r8jzsv4p.adobestats.io,AD-BAN
  - DOMAIN,y53h2xkr61.adobestats.io,AD-BAN
  - DOMAIN,y8f3hhzhsk.adobestats.io,AD-BAN
  - DOMAIN,yaxne83fvv.adobestats.io,AD-BAN
  - DOMAIN,yb6j6g0r1n.adobestats.io,AD-BAN
  - DOMAIN,yj8yx3y8zo.adobestats.io,AD-BAN
  - DOMAIN,yri0bsu0ak.adobestats.io,AD-BAN
  - DOMAIN,yshuhythub.adobestats.io,AD-BAN
  - DOMAIN,yuzuoqo0il.adobestats.io,AD-BAN
  - DOMAIN,z2cez9qgcl.adobestats.io,AD-BAN
  - DOMAIN,z2yohmd1jm.adobestats.io,AD-BAN
  - DOMAIN,z3shmocdp4.adobestats.io,AD-BAN
  - DOMAIN,zekdqanici.adobestats.io,AD-BAN
  - DOMAIN,zfzx6hae4g.adobestats.io,AD-BAN
  - DOMAIN,zmg3v61bbr.adobestats.io,AD-BAN
  - DOMAIN,zooyvml70k.adobestats.io,AD-BAN
  - DOMAIN,zqr7f445uc.adobestats.io,AD-BAN
  - DOMAIN,zr60t8ia88.adobestats.io,AD-BAN
  - DOMAIN,zrao5tdh1t.adobestats.io,AD-BAN
  - DOMAIN,zrbzvc9mel.adobestats.io,AD-BAN
  - DOMAIN,zu8yy3jkaz.adobestats.io,AD-BAN
  - DOMAIN,zz8r2o83on.adobestats.io,AD-BAN
  - DOMAIN,6ll72mpyxv.adobestats.io,AD-BAN
  - DOMAIN,g6elufzgx7.adobestats.io,AD-BAN
  - DOMAIN,gdtbhgs27n.adobestats.io,AD-BAN
  - DOMAIN,hciylk3wpv.adobestats.io,AD-BAN
  - DOMAIN,m8c5gtovwb.adobestats.io,AD-BAN
  - DOMAIN,411r4c18df.adobestats.io,AD-BAN
  - DOMAIN,475ao55klh.adobestats.io,AD-BAN
  - DOMAIN,c0cczlv877.adobestats.io,AD-BAN
  - DOMAIN,fsx0pbg4rz.adobestats.io,AD-BAN
  - DOMAIN,powfb7xi5v.adobestats.io,AD-BAN
  - DOMAIN,h3hqd6gjkd.adobestats.io,AD-BAN
  - DOMAIN,bvcj3prq1u.adobestats.io,AD-BAN
  - DOMAIN,0k6cw37ajl.adobestats.io,AD-BAN
  - DOMAIN,15phzfr05l.adobestats.io,AD-BAN
  - DOMAIN,2os6jhr955.adobestats.io,AD-BAN
  - DOMAIN,3rm6l6bqwd.adobestats.io,AD-BAN
  - DOMAIN,42fkk06z8c.adobestats.io,AD-BAN
  - DOMAIN,45gnbb50sn.adobestats.io,AD-BAN
  - DOMAIN,6482jlr7qo.adobestats.io,AD-BAN
  - DOMAIN,7lj6w2xxew.adobestats.io,AD-BAN
  - DOMAIN,8eptecerpq.adobestats.io,AD-BAN
  - DOMAIN,9k4qeathc0.adobestats.io,AD-BAN
  - DOMAIN,9yod0aafmi.adobestats.io,AD-BAN
  - DOMAIN,dr1wq4uepg.adobestats.io,AD-BAN
  - DOMAIN,i48z07b7gr.adobestats.io,AD-BAN
  - DOMAIN,me7z7bchov.adobestats.io,AD-BAN
  - DOMAIN,mvnfbgfx93.adobestats.io,AD-BAN
  - DOMAIN,nj9rqrql3b.adobestats.io,AD-BAN
  - DOMAIN,ns6ckzkjzg.adobestats.io,AD-BAN
  - DOMAIN,ouovuyeiee.adobestats.io,AD-BAN
  - DOMAIN,tld9di3jxu.adobestats.io,AD-BAN
  - DOMAIN,xa8g202i4u.adobestats.io,AD-BAN
  - DOMAIN,z83qksw5cq.adobestats.io,AD-BAN
  - DOMAIN,9mblf9n5zf.adobestats.io,AD-BAN
  - DOMAIN,be5d7iw6y1.adobestats.io,AD-BAN
  - DOMAIN,cxqenfk6in.adobestats.io,AD-BAN
  - DOMAIN,cim9wvs3is.adobestats.io,AD-BAN
  - DOMAIN,iqhvrdhql4.adobestats.io,AD-BAN
  - DOMAIN,ar1hqm61sk.adobestats.io,AD-BAN
  - DOMAIN,cducupwlaq.adobestats.io,AD-BAN
  - DOMAIN,sap3m7umfu.adobestats.io,AD-BAN
  - DOMAIN,ay8wypezvi.adobestats.io,AD-BAN
  - DOMAIN,1j3muid89l.adobestats.io,AD-BAN
  - DOMAIN,8167gz60t1.adobestats.io,AD-BAN
  - DOMAIN,2bns2f5eza.adobestats.io,AD-BAN
  - DOMAIN,2c3bqjchr6.adobestats.io,AD-BAN
  - DOMAIN,49vfady5kf.adobestats.io,AD-BAN
  - DOMAIN,7v0i13wiuf.adobestats.io,AD-BAN
  - DOMAIN,ak1ow4e0u3.adobestats.io,AD-BAN
  - DOMAIN,f8m1p3tltt.adobestats.io,AD-BAN
  - DOMAIN,l6uu15bwug.adobestats.io,AD-BAN
  - DOMAIN,rtfuwp21b3.adobestats.io,AD-BAN
  - DOMAIN,s8liwh6vbn.adobestats.io,AD-BAN
  - DOMAIN,ok02isdwcx.adobestats.io,AD-BAN
  - DOMAIN,c72tusw5wi.adobestats.io,AD-BAN
  - DOMAIN,dqaytc21nb.adobestats.io,AD-BAN
  - DOMAIN,gm2ai4nsfq.adobestats.io,AD-BAN
  - DOMAIN,hs6dwhuiwh.adobestats.io,AD-BAN
  - DOMAIN,kst1t43sji.adobestats.io,AD-BAN
  - DOMAIN,x12wor9jo6.adobestats.io,AD-BAN
  - DOMAIN,xgj8lmrcy6.adobestats.io,AD-BAN
  - DOMAIN,6unmig6t9w.adobestats.io,AD-BAN
  - DOMAIN,36ai1uk1z7.adobestats.io,AD-BAN
  - DOMAIN,8nft9ke95j.adobestats.io,AD-BAN
  - DOMAIN,9sg9gr4zf4.adobestats.io,AD-BAN
  - DOMAIN,tagtjqcvqg.adobestats.io,AD-BAN
  - DOMAIN,ztxgqqizv7.adobestats.io,AD-BAN
  - DOMAIN,7mw85h5tv4.adobestats.io,AD-BAN
  - DOMAIN,5amul9liob.adobestats.io,AD-BAN
  - DOMAIN,cfh5v77fsy.adobestats.io,AD-BAN
  - DOMAIN,dobw5hakm0.adobestats.io,AD-BAN
  - DOMAIN,08n59yhbxn.adobestats.io,AD-BAN
  - DOMAIN,0p73385wa6.adobestats.io,AD-BAN
  - DOMAIN,0vrs1f5fso.adobestats.io,AD-BAN
  - DOMAIN,5et944c3kg.adobestats.io,AD-BAN
  - DOMAIN,610o7ktxw7.adobestats.io,AD-BAN
  - DOMAIN,b8qwvscik0.adobestats.io,AD-BAN
  - DOMAIN,cvl65mxwmh.adobestats.io,AD-BAN
  - DOMAIN,dtt06hnkyj.adobestats.io,AD-BAN
  - DOMAIN,fg7bb8gi6d.adobestats.io,AD-BAN
  - DOMAIN,iy304996hm.adobestats.io,AD-BAN
  - DOMAIN,lp4og15wl5.adobestats.io,AD-BAN
  - DOMAIN,nxq02alk63.adobestats.io,AD-BAN
  - DOMAIN,ofgajs60g1.adobestats.io,AD-BAN
  - DOMAIN,om52ny8l9s.adobestats.io,AD-BAN
  - DOMAIN,s14z1kt85g.adobestats.io,AD-BAN
  - DOMAIN,tyqs8bsps8.adobestats.io,AD-BAN
  - DOMAIN,vvpexgmc5t.adobestats.io,AD-BAN
  - DOMAIN,w3ffpxhbn6.adobestats.io,AD-BAN
  - DOMAIN,w58drkayqf.adobestats.io,AD-BAN
  - DOMAIN,w8mvrujj91.adobestats.io,AD-BAN
  - DOMAIN,wjpmg2uott.adobestats.io,AD-BAN
  - DOMAIN,xljz63k33x.adobestats.io,AD-BAN
  - DOMAIN,7micpuqiwp.adobestats.io,AD-BAN
  - DOMAIN,2lb39igrph.adobestats.io,AD-BAN
  - DOMAIN,3zgi4mscuk.adobestats.io,AD-BAN
  - DOMAIN,elf5yl77ju.adobestats.io,AD-BAN
  - DOMAIN,ktb8rx6uhe.adobestats.io,AD-BAN
  - DOMAIN,heufuideue.adobestats.io,AD-BAN
  - DOMAIN,xq68npgl4w.adobestats.io,AD-BAN
  - DOMAIN,vnm70hlbn4.adobestats.io,AD-BAN
  - DOMAIN,p4hiwy76wl.adobestats.io,AD-BAN
  - DOMAIN,q7i4awui0j.adobestats.io,AD-BAN
  - DOMAIN,soirhk7bm2.adobestats.io,AD-BAN
  - DOMAIN,0789i4f3cq.adobestats.io,AD-BAN
  - DOMAIN,827x3zvk4q.adobestats.io,AD-BAN
  - DOMAIN,8ljcntz31v.adobestats.io,AD-BAN
  - DOMAIN,95yojg6epq.adobestats.io,AD-BAN
  - DOMAIN,9wcrtdzcti.adobestats.io,AD-BAN
  - DOMAIN,a3dxeq2iq9.adobestats.io,AD-BAN
  - DOMAIN,hrfn4gru1j.adobestats.io,AD-BAN
  - DOMAIN,kx8yghodgl.adobestats.io,AD-BAN
  - DOMAIN,olh5t1ccns.adobestats.io,AD-BAN
  - DOMAIN,svcgy434g6.adobestats.io,AD-BAN
  - DOMAIN,uwr2upexhs.adobestats.io,AD-BAN
  - DOMAIN,wk0sculz2x.adobestats.io,AD-BAN
  - DOMAIN,xbhspynj8t.adobestats.io,AD-BAN
  - DOMAIN,xod1t4qsyk.adobestats.io,AD-BAN
  - DOMAIN,iu7mq0jcce.adobestats.io,AD-BAN
  - DOMAIN,tdatxzi3t4.adobestats.io,AD-BAN
  - DOMAIN,rptowanjjh.adobestats.io,AD-BAN
  - DOMAIN,3cnu7l5q8s.adobestats.io,AD-BAN
  - DOMAIN,ow1o9yr32j.adobestats.io,AD-BAN
  - DOMAIN,bc27a8e3zw.adobestats.io,AD-BAN
  - DOMAIN,ok6tbgxfta.adobestats.io,AD-BAN
  - DOMAIN,9nqvoa544j.adobestats.io,AD-BAN
  - DOMAIN,arzggvbs37.adobestats.io,AD-BAN
  - DOMAIN,d8hof9a6gg.adobestats.io,AD-BAN
  - DOMAIN,qh0htdwe2n.adobestats.io,AD-BAN
  - DOMAIN,fu9wr8tk0u.adobestats.io,AD-BAN
  - DOMAIN,0ss1vovh4a.adobestats.io,AD-BAN
  - DOMAIN,15ousmguga.adobestats.io,AD-BAN
  - DOMAIN,3oidzvonpa.adobestats.io,AD-BAN
  - DOMAIN,5pjcqccrcu.adobestats.io,AD-BAN
  - DOMAIN,75ffpy5iio.adobestats.io,AD-BAN
  - DOMAIN,7fj42ny0sd.adobestats.io,AD-BAN
  - DOMAIN,drwizwikc0.adobestats.io,AD-BAN
  - DOMAIN,fl34tml8is.adobestats.io,AD-BAN
  - DOMAIN,kd4c3z4xbz.adobestats.io,AD-BAN
  - DOMAIN,ksw6oyvdk6.adobestats.io,AD-BAN
  - DOMAIN,l91nnnkmbi.adobestats.io,AD-BAN
  - DOMAIN,ln3pv36xx8.adobestats.io,AD-BAN
  - DOMAIN,m5cgk2pkdn.adobestats.io,AD-BAN
  - DOMAIN,nj66fd4dzr.adobestats.io,AD-BAN
  - DOMAIN,nl00xmmmn5.adobestats.io,AD-BAN
  - DOMAIN,wn9kta1iw4.adobestats.io,AD-BAN
  - DOMAIN,x3sszs7ihy.adobestats.io,AD-BAN
  - DOMAIN,nrenlhdc1t.adobestats.io,AD-BAN
  - DOMAIN,6nbt0kofc7.adobestats.io,AD-BAN
  - DOMAIN,kmqhqhs02w.adobestats.io,AD-BAN
  - DOMAIN,wdyav7y3rf.adobestats.io,AD-BAN
  - DOMAIN,3ysvacl1hb.adobestats.io,AD-BAN
  - DOMAIN,bqbvmlmtmo.adobestats.io,AD-BAN
  - DOMAIN,zn0o46rt48.adobestats.io,AD-BAN
  - DOMAIN,8mtavkaq40.adobestats.io,AD-BAN
  - DOMAIN,52h0nva0wa.adobestats.io,AD-BAN
  - DOMAIN,4t5jyh9fkk.adobestats.io,AD-BAN
  - DOMAIN,hen2jsru7c.adobestats.io,AD-BAN
  - DOMAIN,6tpqsy07cp.adobestats.io,AD-BAN
  - DOMAIN,0andkf1e8e.adobestats.io,AD-BAN
  - DOMAIN,2kc4lqhpto.adobestats.io,AD-BAN
  - DOMAIN,43q1uykg1z.adobestats.io,AD-BAN
  - DOMAIN,7zak80l8ic.adobestats.io,AD-BAN
  - DOMAIN,9dal0pbsx3.adobestats.io,AD-BAN
  - DOMAIN,9rcgbke6qx.adobestats.io,AD-BAN
  - DOMAIN,cwejcdduvp.adobestats.io,AD-BAN
  - DOMAIN,dq1gubixz7.adobestats.io,AD-BAN
  - DOMAIN,fc2k38te2m.adobestats.io,AD-BAN
  - DOMAIN,i1j2plx3mv.adobestats.io,AD-BAN
  - DOMAIN,lnosso28q5.adobestats.io,AD-BAN
  - DOMAIN,npt74s16x9.adobestats.io,AD-BAN
  - DOMAIN,o6pk3ypjcf.adobestats.io,AD-BAN
  - DOMAIN,pcmdl6zcfd.adobestats.io,AD-BAN
  - DOMAIN,q0z6ycmvhl.adobestats.io,AD-BAN
  - DOMAIN,quptxdg94y.adobestats.io,AD-BAN
  - DOMAIN,s4y2s7r9ah.adobestats.io,AD-BAN
  - DOMAIN,yajkeabyrj.adobestats.io,AD-BAN
  - DOMAIN,r9qg11e83v.adobestats.io,AD-BAN
  - DOMAIN,13hceguz11.adobestats.io,AD-BAN
  - DOMAIN,4xosvsrdto.adobestats.io,AD-BAN
  - DOMAIN,72p3yx09zx.adobestats.io,AD-BAN
  - DOMAIN,7gu7j31tn3.adobestats.io,AD-BAN
  - DOMAIN,hob0cz1xnx.adobestats.io,AD-BAN
  - DOMAIN,fp.adobestats.io,AD-BAN
  - DOMAIN,6woibl6fiu.adobestats.io,AD-BAN
  - DOMAIN,jh34ro8dm2.adobestats.io,AD-BAN
  - DOMAIN,sz2edaz2s9.adobestats.io,AD-BAN
  - DOMAIN,4s6bg7xces.adobestats.io,AD-BAN
  - DOMAIN,3d5rp7oyng.adobestats.io,AD-BAN
  - DOMAIN,5dec9025sr.adobestats.io,AD-BAN
  - DOMAIN,5muggmgxyb.adobestats.io,AD-BAN
  - DOMAIN,94enlu8vov.adobestats.io,AD-BAN
  - DOMAIN,9pa13v8uko.adobestats.io,AD-BAN
  - DOMAIN,csb8usj9o4.adobestats.io,AD-BAN
  - DOMAIN,dxegvh5wpp.adobestats.io,AD-BAN
  - DOMAIN,itiabkzm7h.adobestats.io,AD-BAN
  - DOMAIN,jsusbknzle.adobestats.io,AD-BAN
  - DOMAIN,tzbl46vv9o.adobestats.io,AD-BAN
  - DOMAIN,v5zm23ixg2.adobestats.io,AD-BAN
  - DOMAIN,w9m8uwm145.adobestats.io,AD-BAN
  - DOMAIN,zf37mp80xx.adobestats.io,AD-BAN
  - DOMAIN,gyt27lbjb3.adobestats.io,AD-BAN
  - DOMAIN,3m3e8ccqyo.adobestats.io,AD-BAN
  - DOMAIN,2sug8qxjag.adobestats.io,AD-BAN
  - DOMAIN,36ivntopuj.adobestats.io,AD-BAN
  - DOMAIN,1eqkbrjz78.adobestats.io,AD-BAN
  - DOMAIN,szvbv5h62r.adobestats.io,AD-BAN
  - DOMAIN,zf1aegmmle.adobestats.io,AD-BAN
  - DOMAIN,50lifxkein.adobestats.io,AD-BAN
  - DOMAIN,dfwv44wffr.adobestats.io,AD-BAN
  - DOMAIN,qwzzhqpliv.adobestats.io,AD-BAN
  - DOMAIN,0wcraxg290.adobestats.io,AD-BAN
  - DOMAIN,gpd3r2mkgs.adobestats.io,AD-BAN
  - DOMAIN,116n6tkxyr.adobestats.io,AD-BAN
  - DOMAIN,3nkkaf8h85.adobestats.io,AD-BAN
  - DOMAIN,55oguiniw8.adobestats.io,AD-BAN
  - DOMAIN,e1tyeiimw3.adobestats.io,AD-BAN
  - DOMAIN,g7zh7zqzqx.adobestats.io,AD-BAN
  - DOMAIN,gglnjgxaia.adobestats.io,AD-BAN
  - DOMAIN,h33a7kps0t.adobestats.io,AD-BAN
  - DOMAIN,jewn0nrrp8.adobestats.io,AD-BAN
  - DOMAIN,r7sawld5l6.adobestats.io,AD-BAN
  - DOMAIN,vodh16neme.adobestats.io,AD-BAN
  - DOMAIN,wntfgdo4ki.adobestats.io,AD-BAN
  - DOMAIN,x9u2jsesk0.adobestats.io,AD-BAN
  - DOMAIN,xsn76p7ntx.adobestats.io,AD-BAN
  - DOMAIN,xz9xjlyw58.adobestats.io,AD-BAN
  - DOMAIN,as73qhl83n.adobestats.io,AD-BAN
  - DOMAIN,b0giyj3mc1.adobestats.io,AD-BAN
  - DOMAIN,f9554salkg.adobestats.io,AD-BAN
  - DOMAIN,i487nlno13.adobestats.io,AD-BAN
  - DOMAIN,qx2t3lrpmg.adobestats.io,AD-BAN
  - DOMAIN,r0exxqftud.adobestats.io,AD-BAN
  - DOMAIN,spbuswk2di.adobestats.io,AD-BAN
  - DOMAIN,swxs9c0fpt.adobestats.io,AD-BAN
  - DOMAIN,v7esmx1n0s.adobestats.io,AD-BAN
  - DOMAIN,zglaizubbj.adobestats.io,AD-BAN
  - DOMAIN,22wqqv6b23.adobestats.io,AD-BAN
  - DOMAIN,5jdb1nfklf.adobestats.io,AD-BAN
  - DOMAIN,6glym36rbb.adobestats.io,AD-BAN
  - DOMAIN,6h8391pvf8.adobestats.io,AD-BAN
  - DOMAIN,c675s4pigj.adobestats.io,AD-BAN
  - DOMAIN,c8pyxo4r20.adobestats.io,AD-BAN
  - DOMAIN,co9sg87h3h.adobestats.io,AD-BAN
  - DOMAIN,f8wflegco1.adobestats.io,AD-BAN
  - DOMAIN,g6ld7orx5r.adobestats.io,AD-BAN
  - DOMAIN,r00r33ldza.adobestats.io,AD-BAN
  - DOMAIN,scmnpedxm0.adobestats.io,AD-BAN
  - DOMAIN,slx5l73jwh.adobestats.io,AD-BAN
  - DOMAIN,w8yfgti2yd.adobestats.io,AD-BAN
  - DOMAIN,yljkdk5tky.adobestats.io,AD-BAN
  - DOMAIN,0oydr1f856.adobestats.io,AD-BAN
  - DOMAIN,3ea8nnv3fo.adobestats.io,AD-BAN
  - DOMAIN,4j225l63ny.adobestats.io,AD-BAN
  - DOMAIN,4pbmn87uov.adobestats.io,AD-BAN
  - DOMAIN,8z20kcq3af.adobestats.io,AD-BAN
  - DOMAIN,bp5qqybokw.adobestats.io,AD-BAN
  - DOMAIN,dri0xipdj1.adobestats.io,AD-BAN
  - DOMAIN,e8yny99m61.adobestats.io,AD-BAN
  - DOMAIN,etqjl6s9m9.adobestats.io,AD-BAN
  - DOMAIN,iyuzq3njtk.adobestats.io,AD-BAN
  - DOMAIN,k2zeiskfro.adobestats.io,AD-BAN
  - DOMAIN,kk6mqz4ho1.adobestats.io,AD-BAN
  - DOMAIN,ltby3lmge7.adobestats.io,AD-BAN
  - DOMAIN,m07jtnnega.adobestats.io,AD-BAN
  - DOMAIN,o9617jdaiw.adobestats.io,AD-BAN
  - DOMAIN,ry9atn2zzw.adobestats.io,AD-BAN
  - DOMAIN,t8nxhdgbcb.adobestats.io,AD-BAN
  - DOMAIN,yhxcdjy2st.adobestats.io,AD-BAN
  - DOMAIN,1yzch4f7fj.adobestats.io,AD-BAN
  - DOMAIN,2dym9ld8t4.adobestats.io,AD-BAN
  - DOMAIN,7857z7jy1n.adobestats.io,AD-BAN
  - DOMAIN,917wzppd6w.adobestats.io,AD-BAN
  - DOMAIN,acakpm3wmd.adobestats.io,AD-BAN
  - DOMAIN,ah0uf3uzwe.adobestats.io,AD-BAN
  - DOMAIN,anllgxlrgl.adobestats.io,AD-BAN
  - DOMAIN,ar3zpq1idw.adobestats.io,AD-BAN
  - DOMAIN,as15ffplma.adobestats.io,AD-BAN
  - DOMAIN,b343x3kjgp.adobestats.io,AD-BAN
  - DOMAIN,b4ur7jk78w.adobestats.io,AD-BAN
  - DOMAIN,c7udtzsk2j.adobestats.io,AD-BAN
  - DOMAIN,dt549nqpx7.adobestats.io,AD-BAN
  - DOMAIN,f7ul6vs4ha.adobestats.io,AD-BAN
  - DOMAIN,hbejpf1qou.adobestats.io,AD-BAN
  - DOMAIN,s6195z8x2q.adobestats.io,AD-BAN
  - DOMAIN,smtcbgh2n7.adobestats.io,AD-BAN
  - DOMAIN,v5f89yjtcw.adobestats.io,AD-BAN
  - DOMAIN,x66v4qn2t7.adobestats.io,AD-BAN
  - DOMAIN,yvbzqwn2gz.adobestats.io,AD-BAN
  - DOMAIN,1ompyaokc3.adobestats.io,AD-BAN
  - DOMAIN,2ent6j0ret.adobestats.io,AD-BAN
  - DOMAIN,7860w7avqe.adobestats.io,AD-BAN
  - DOMAIN,kqs7x93q8r.adobestats.io,AD-BAN
  - DOMAIN,now8wpo1bv.adobestats.io,AD-BAN
  - DOMAIN,oeab9s6dtf.adobestats.io,AD-BAN
  - DOMAIN,p4apxcgh7b.adobestats.io,AD-BAN
  - DOMAIN,rs2deio0ks.adobestats.io,AD-BAN
  - DOMAIN,wfyeckyxxx.adobestats.io,AD-BAN
  - DOMAIN,xngv0345gb.adobestats.io,AD-BAN
  - DOMAIN,5nae7ued1i.adobestats.io,AD-BAN
  - DOMAIN,74jqw6xdam.adobestats.io,AD-BAN
  - DOMAIN,9xxyu4ncc9.adobestats.io,AD-BAN
  - DOMAIN,ckh0swnp4c.adobestats.io,AD-BAN
  - DOMAIN,dr02lso5fh.adobestats.io,AD-BAN
  - DOMAIN,et3x020m0i.adobestats.io,AD-BAN
  - DOMAIN,g58jqxdh3y.adobestats.io,AD-BAN
  - DOMAIN,j7wq25n7dy.adobestats.io,AD-BAN
  - DOMAIN,a69wv3f4j3.adobestats.io,AD-BAN
  - DOMAIN,jwi6q78hu2.adobestats.io,AD-BAN
  - DOMAIN,nw3ft2wlrn.adobestats.io,AD-BAN
  - DOMAIN,yykww43js1.adobestats.io,AD-BAN
  - DOMAIN,12ihfrf869.adobestats.io,AD-BAN
  - DOMAIN,a5dtr1c4er.adobestats.io,AD-BAN
  - DOMAIN,ajs31fsy2t.adobestats.io,AD-BAN
  - DOMAIN,mi9rav314a.adobestats.io,AD-BAN
  - DOMAIN,z66m01zo11.adobestats.io,AD-BAN
  - DOMAIN,vd8bjo50bv.adobestats.io,AD-BAN
  - DOMAIN,tqcbs617dw.adobe.io,AD-BAN
  - DOMAIN,fcbx058i0c.adobe.io,AD-BAN
  - DOMAIN,chlydkc9bz.adobe.io,AD-BAN
  - DOMAIN,4f1b1vqcfi.adobestats.io,AD-BAN
  - DOMAIN,ci5yrifbog.adobestats.io,AD-BAN
  - DOMAIN,vn4waib0dk.adobestats.io,AD-BAN
  - DOMAIN,drdqxhlcop.adobe.io,AD-BAN
  - DOMAIN,1i09xck9hj.adobestats.io,AD-BAN
  - DOMAIN,3reg39xtkp.adobestats.io,AD-BAN
  - DOMAIN,quij2u03a1.adobestats.io,AD-BAN
  - DOMAIN,xo9j8bcw4a.adobe.io,AD-BAN
  - DOMAIN,37c3yfb1t4.adobestats.io,AD-BAN
  - DOMAIN,72xoz2f3v6.adobestats.io,AD-BAN
  - DOMAIN,be26lkdm4q.adobestats.io,AD-BAN
  - DOMAIN,y9n9ngtvna.adobestats.io,AD-BAN
  - DOMAIN,4psx0dt6zg.adobestats.io,AD-BAN
  - DOMAIN,6pv0uu0vny.adobestats.io,AD-BAN
  - DOMAIN,9b2hch4xc9.adobestats.io,AD-BAN
  - DOMAIN,9wbdpkyfsz.adobestats.io,AD-BAN
  - DOMAIN,ekt43qq0wo.adobestats.io,AD-BAN
  - DOMAIN,h1xtbu1sca.adobestats.io,AD-BAN
  - DOMAIN,hdym10nr7u.adobestats.io,AD-BAN
  - DOMAIN,hmnzwq6owm.adobestats.io,AD-BAN
  - DOMAIN,hvww1kah7v.adobestats.io,AD-BAN
  - DOMAIN,jkt1n3vsxr.adobestats.io,AD-BAN
  - DOMAIN,nth06aynso.adobestats.io,AD-BAN
  - DOMAIN,q4ajvptsj7.adobestats.io,AD-BAN
  - DOMAIN,t8ckmbunss.adobestats.io,AD-BAN
  - DOMAIN,x1mmbszh12.adobestats.io,AD-BAN
  - DOMAIN,y8x0fb0tdr.adobestats.io,AD-BAN
  - DOMAIN,hy1ykx5mvp.adobestats.io,AD-BAN
  - DOMAIN,yl2744311i.adobestats.io,AD-BAN
  - DOMAIN,fuindpvfok.adobestats.io,AD-BAN
  - DOMAIN,699yxd2304.adobestats.io,AD-BAN
  - DOMAIN,6t47fd4rda.adobestats.io,AD-BAN
  - DOMAIN,lpm2ewb43r.adobestats.io,AD-BAN
  - DOMAIN,mktnq8n4qv.adobestats.io,AD-BAN
  - DOMAIN,xuk3z0wfkn.adobestats.io,AD-BAN
  - DOMAIN,1s97z9hn4o.adobestats.io,AD-BAN
  - DOMAIN,fmbxa3a0yh.adobestats.io,AD-BAN
  - DOMAIN,ywwlnskz2q.adobestats.io,AD-BAN
  - DOMAIN,a2104gz1mh.adobe.io,AD-BAN
  - DOMAIN,0ojupfm51u.adobe.io,AD-BAN
  - DOMAIN,4zong3qp04.adobestats.io,AD-BAN
  - DOMAIN,giq5q50mql.adobestats.io,AD-BAN
  - DOMAIN,vs8cvtxb6h.adobestats.io,AD-BAN
  - DOMAIN,3f3h0nltvv.adobestats.io,AD-BAN
  - DOMAIN,9f0nec97jl.adobestats.io,AD-BAN
  - DOMAIN,a781lq3dl1.adobestats.io,AD-BAN
  - DOMAIN,cqtur9nf2j.adobestats.io,AD-BAN
  - DOMAIN,d13qjllccx.adobestats.io,AD-BAN
  - DOMAIN,e94c9o627h.adobestats.io,AD-BAN
  - DOMAIN,g25js6o5zn.adobestats.io,AD-BAN
  - DOMAIN,grzjv3nyau.adobestats.io,AD-BAN
  - DOMAIN,j0c7zaivwa.adobestats.io,AD-BAN
  - DOMAIN,j7d199wwp8.adobestats.io,AD-BAN
  - DOMAIN,o75l4dlkbh.adobestats.io,AD-BAN
  - DOMAIN,sgg0nltplg.adobestats.io,AD-BAN
  - DOMAIN,uiktuww26f.adobestats.io,AD-BAN
  - DOMAIN,wojee26p4t.adobestats.io,AD-BAN
  - DOMAIN,xm0yibvxj5.adobestats.io,AD-BAN
  - DOMAIN,y1usv3l35k.adobestats.io,AD-BAN
  - DOMAIN,yaxvhurwoa.adobestats.io,AD-BAN
  - DOMAIN,1w46mavare.adobestats.io,AD-BAN
  - DOMAIN,lhdf90vxbv.adobestats.io,AD-BAN
  - DOMAIN,wrtafci7rp.adobestats.io,AD-BAN
  - DOMAIN,4f8y6z3snu.adobestats.io,AD-BAN
  - DOMAIN,frkjjsdxae.adobestats.io,AD-BAN
  - DOMAIN,iahl4jjb56.adobestats.io,AD-BAN
  - DOMAIN,t5k3ioz4p2.adobestats.io,AD-BAN
  - DOMAIN,5fw2aensgd.adobestats.io,AD-BAN
  - DOMAIN,c8epvys0ps.adobestats.io,AD-BAN
  - DOMAIN,rr9nn5x1fh.adobestats.io,AD-BAN
  - DOMAIN,ubxajwohoi.adobestats.io,AD-BAN
  - DOMAIN,gsd14enp3n.adobestats.io,AD-BAN
  - DOMAIN,rshw2d4xt2.adobestats.io,AD-BAN
  - DOMAIN,a43dmjfhi6.adobestats.io,AD-BAN
  - DOMAIN,5rzen92rqw.adobestats.io,AD-BAN
  - DOMAIN,zhsq65iox8.adobestats.io,AD-BAN
  - DOMAIN,5249gprdc8.adobestats.io,AD-BAN
  - DOMAIN,5yhf2ygy0v.adobestats.io,AD-BAN
  - DOMAIN,64aui0lmm8.adobestats.io,AD-BAN
  - DOMAIN,9ksdhwfj1i.adobestats.io,AD-BAN
  - DOMAIN,ay4wu1tp41.adobestats.io,AD-BAN
  - DOMAIN,e3ddirlhb0.adobestats.io,AD-BAN
  - DOMAIN,huk9szui57.adobestats.io,AD-BAN
  - DOMAIN,kvew1ycx60.adobestats.io,AD-BAN
  - DOMAIN,l3t2s6mj4w.adobestats.io,AD-BAN
  - DOMAIN,mr9hl8gv47.adobestats.io,AD-BAN
  - DOMAIN,n8lqv6j4yr.adobestats.io,AD-BAN
  - DOMAIN,omx332339b.adobestats.io,AD-BAN
  - DOMAIN,sas2o2lo36.adobestats.io,AD-BAN
  - DOMAIN,vgieu16g7s.adobestats.io,AD-BAN
  - DOMAIN,w25ijw4ebd.adobestats.io,AD-BAN
  - DOMAIN,wyxrzcfpte.adobestats.io,AD-BAN
  - DOMAIN,93up6jlw8l.adobestats.io,AD-BAN
  - DOMAIN,ui5m4exlcw.adobestats.io,AD-BAN
  - DOMAIN,04jkjo2db5.adobestats.io,AD-BAN
  - DOMAIN,20x112xlz4.adobestats.io,AD-BAN
  - DOMAIN,osp3g9p4c9.adobestats.io,AD-BAN
  - DOMAIN,dmi13b9vlo.adobestats.io,AD-BAN
  - DOMAIN,pndiszyo9k.adobestats.io,AD-BAN
  - DOMAIN,f162lqu11i.adobestats.io,AD-BAN
  - DOMAIN,4u4udfpb9h.adobe.io,AD-BAN
  - DOMAIN,oz5i3yutuw.adobestats.io,AD-BAN
  - DOMAIN,dn0sbkqqfk.adobestats.io,AD-BAN
  - DOMAIN,ed3bl6kidt.adobestats.io,AD-BAN
  - DOMAIN,kw2z4tkbb6.adobestats.io,AD-BAN
  - DOMAIN,v7jyeimrye.adobestats.io,AD-BAN
  - DOMAIN,y6950iur2g.adobestats.io,AD-BAN
  - DOMAIN,9k046300lp.adobe.io,AD-BAN
  - DOMAIN,rzrxmjzfdn.adobestats.io,AD-BAN
  - DOMAIN,ef7m2t2zz9.adobestats.io,AD-BAN
  - DOMAIN,5tlyaxuuph.adobestats.io,AD-BAN
  - DOMAIN,b37k7g9c3q.adobestats.io,AD-BAN
  - DOMAIN,h4eiodaymd.adobestats.io,AD-BAN
  - DOMAIN,vyho44iygi.adobestats.io,AD-BAN
  - DOMAIN,3kqudwluux.adobestats.io,AD-BAN
  - DOMAIN,4g1n9wc25y.adobestats.io,AD-BAN
  - DOMAIN,4z1zypgkef.adobestats.io,AD-BAN
  - DOMAIN,548g5qdx3a.adobestats.io,AD-BAN
  - DOMAIN,9v2nxvmwto.adobestats.io,AD-BAN
  - DOMAIN,ewcovphpsa.adobestats.io,AD-BAN
  - DOMAIN,k0at187jqk.adobestats.io,AD-BAN
  - DOMAIN,r0xv19ou69.adobestats.io,AD-BAN
  - DOMAIN,ujzflw123x.adobestats.io,AD-BAN
  - DOMAIN,vx9xh18ov9.adobestats.io,AD-BAN
  - DOMAIN,wvyb3i4jf9.adobestats.io,AD-BAN
  - DOMAIN,xcna71ygzo.adobestats.io,AD-BAN
  - DOMAIN,zsursdyz0d.adobestats.io,AD-BAN
  - DOMAIN,idd3z8uis9.adobestats.io,AD-BAN
  - DOMAIN,xeh65lseqp.adobestats.io,AD-BAN
  - DOMAIN,htyt9ah5l0.adobestats.io,AD-BAN
  - DOMAIN,ld090pbtrm.adobestats.io,AD-BAN
  - DOMAIN,9c7tz4k81b.adobestats.io,AD-BAN
  - DOMAIN,c0acub5mul.adobestats.io,AD-BAN
  - DOMAIN,z06nr7yct1.adobestats.io,AD-BAN
  - DOMAIN,p1ev0qf92u.adobestats.io,AD-BAN
  - DOMAIN,rnkix8uugk.adobestats.io,AD-BAN
  - DOMAIN,xu2ws3lrz4.adobestats.io,AD-BAN
  - DOMAIN,yjry12zotn.adobestats.io,AD-BAN
  - DOMAIN,atn3a2qrbo.adobestats.io,AD-BAN
  - DOMAIN,hl0f6tmk0r.adobestats.io,AD-BAN
  - DOMAIN,3mmyrmpxdx.adobestats.io,AD-BAN
  - DOMAIN,8burj9rb4s.adobestats.io,AD-BAN
  - DOMAIN,8ondwicgpd.adobestats.io,AD-BAN
  - DOMAIN,i48sv1cxi0.adobestats.io,AD-BAN
  - DOMAIN,0qnxjg7wfg.adobestats.io,AD-BAN
  - DOMAIN,wzn00xy2ww.adobestats.io,AD-BAN
  - DOMAIN,1oh17981n9.adobestats.io,AD-BAN
  - DOMAIN,63rbu8oiz9.adobestats.io,AD-BAN
  - DOMAIN,674gbmmxoi.adobestats.io,AD-BAN
  - DOMAIN,a89bum3ple.adobestats.io,AD-BAN
  - DOMAIN,ck6vzx58v4.adobestats.io,AD-BAN
  - DOMAIN,djrnrt8f6t.adobestats.io,AD-BAN
  - DOMAIN,h6o050q9pf.adobestats.io,AD-BAN
  - DOMAIN,kfej9govhz.adobestats.io,AD-BAN
  - DOMAIN,fipjog5p8f.adobestats.io,AD-BAN
  - DOMAIN,53q3ombk2r.adobestats.io,AD-BAN
  - DOMAIN,7w7gpbzc77.adobestats.io,AD-BAN
  - DOMAIN,9xjyqha9e9.adobestats.io,AD-BAN
  - DOMAIN,jyu43b655u.adobestats.io,AD-BAN
  - DOMAIN,o8xhlbmm82.adobestats.io,AD-BAN
  - DOMAIN,zlzdicvb1y.adobestats.io,AD-BAN
  - DOMAIN,5bcixfkyl5.adobestats.io,AD-BAN
  - DOMAIN,fu4rpw9ku4.adobestats.io,AD-BAN
  - DOMAIN,h4wgsqts2k.adobestats.io,AD-BAN
  - DOMAIN,qlw1ee8xzn.adobestats.io,AD-BAN
  - DOMAIN,wgg7g1om7h.adobestats.io,AD-BAN
  - DOMAIN,wozkyv628d.adobestats.io,AD-BAN
  - DOMAIN,kw31bz1lwj.adobestats.io,AD-BAN
  - DOMAIN,666jnxks4d.adobestats.io,AD-BAN
  - DOMAIN,wujfm82qyd.adobestats.io,AD-BAN
  - DOMAIN,vgetwxoqno.adobe.io,AD-BAN
  - DOMAIN,12zow70qyg.adobestats.io,AD-BAN
  - DOMAIN,17rznd8ped.adobestats.io,AD-BAN
  - DOMAIN,1mqvqabmi0.adobestats.io,AD-BAN
  - DOMAIN,86r5sgpc5i.adobestats.io,AD-BAN
  - DOMAIN,9aa2r7kikj.adobestats.io,AD-BAN
  - DOMAIN,ecdcuflr6b.adobestats.io,AD-BAN
  - DOMAIN,g3x2gf65lr.adobestats.io,AD-BAN
  - DOMAIN,h97lgqk8bo.adobestats.io,AD-BAN
  - DOMAIN,jv4pl10h5s.adobestats.io,AD-BAN
  - DOMAIN,jzh1rdq07h.adobestats.io,AD-BAN
  - DOMAIN,ou6wlq2xxk.adobestats.io,AD-BAN
  - DOMAIN,p2hljfs4ui.adobestats.io,AD-BAN
  - DOMAIN,p5lr643921.adobestats.io,AD-BAN
  - DOMAIN,p882on2mec.adobestats.io,AD-BAN
  - DOMAIN,qrz7h0bk0d.adobestats.io,AD-BAN
  - DOMAIN,tpa7l912ct.adobestats.io,AD-BAN
  - DOMAIN,utl2ryss9g.adobestats.io,AD-BAN
  - DOMAIN,y8nrk9ev78.adobestats.io,AD-BAN
  - DOMAIN,yabyd58pwe.adobestats.io,AD-BAN
  - DOMAIN,yvz37f39o9.adobestats.io,AD-BAN
  - DOMAIN,z9cyo99ees.adobestats.io,AD-BAN
  - DOMAIN,eljpnp7pwp.adobestats.io,AD-BAN
  - DOMAIN,9cq4sjum6s.adobestats.io,AD-BAN
  - DOMAIN,f34mf655aw.adobestats.io,AD-BAN
  - DOMAIN,m4ldtnfvqf.adobestats.io,AD-BAN
  - DOMAIN,3uzm9qfpzw.adobestats.io,AD-BAN
  - DOMAIN,otoaq2y6ha.adobestats.io,AD-BAN
  - DOMAIN,w2tarrtw8t.adobestats.io,AD-BAN
  - DOMAIN,5ehqhq0kgt.adobestats.io,AD-BAN
  - DOMAIN,avwgpydcaz.adobestats.io,AD-BAN
  - DOMAIN,t45y99rpkr.adobestats.io,AD-BAN
  - DOMAIN,7zjom7dijk.adobestats.io,AD-BAN
  - DOMAIN,10a3hujicl.adobestats.io,AD-BAN
  - DOMAIN,5ebbalr27t.adobestats.io,AD-BAN
  - DOMAIN,ai51k25vkp.adobestats.io,AD-BAN
  - DOMAIN,flutt9urxr.adobestats.io,AD-BAN
  - DOMAIN,hpbpvpzb2l.adobestats.io,AD-BAN
  - DOMAIN,jfpuemxvzl.adobestats.io,AD-BAN
  - DOMAIN,lphlawf194.adobestats.io,AD-BAN
  - DOMAIN,m0o17z9ytf.adobestats.io,AD-BAN
  - DOMAIN,s9la1nxlf1.adobestats.io,AD-BAN
  - DOMAIN,5ldhuv8nzy.adobestats.io,AD-BAN
  - DOMAIN,fpaodyl985.adobestats.io,AD-BAN
  - DOMAIN,fypusvplon.adobestats.io,AD-BAN
  - DOMAIN,hgdvggfsuo.adobestats.io,AD-BAN
  - DOMAIN,hnskhe2spg.adobestats.io,AD-BAN
  - DOMAIN,ixlleed9m6.adobestats.io,AD-BAN
  - DOMAIN,mbksaqsgke.adobestats.io,AD-BAN
  - DOMAIN,puk5mdqkx8.adobestats.io,AD-BAN
  - DOMAIN,q11bco3ezj.adobestats.io,AD-BAN
  - DOMAIN,z9d0725u9r.adobestats.io,AD-BAN
  - DOMAIN,bmfyyt6q6g.adobestats.io,AD-BAN
  - DOMAIN,og6u0rueid.adobestats.io,AD-BAN
  - DOMAIN,8i88bcggu6.adobestats.io,AD-BAN
  - DOMAIN,b0qyzgkxcv.adobestats.io,AD-BAN
  - DOMAIN,h0no575qji.adobestats.io,AD-BAN
  - DOMAIN,j2ktcg967p.adobestats.io,AD-BAN
  - DOMAIN,qv3lfs30zn.adobestats.io,AD-BAN
  - DOMAIN,azrbt1iw3j.adobestats.io,AD-BAN
  - DOMAIN,igka06iww4.adobestats.io,AD-BAN
  - DOMAIN,zqby5krery.adobestats.io,AD-BAN
  - DOMAIN,27hqwvagdh.adobe.io,AD-BAN
  - DOMAIN,m6t8sobbc7.adobestats.io,AD-BAN
  - DOMAIN,1k7hno3xrp.adobestats.io,AD-BAN
  - DOMAIN,bw59wxr92v.adobestats.io,AD-BAN
  - DOMAIN,dj06zaouol.adobestats.io,AD-BAN
  - DOMAIN,kgj7bmte19.adobestats.io,AD-BAN
  - DOMAIN,kjbqf1ol9g.adobestats.io,AD-BAN
  - DOMAIN,m1vtal0vxi.adobestats.io,AD-BAN
  - DOMAIN,mmu7w9z4g7.adobestats.io,AD-BAN
  - DOMAIN,rrwch5wg04.adobestats.io,AD-BAN
  - DOMAIN,33dghav1u0.adobestats.io,AD-BAN
  - DOMAIN,3eamcreuvn.adobestats.io,AD-BAN
  - DOMAIN,49xq1olxsn.adobestats.io,AD-BAN
  - DOMAIN,5ywl5monp9.adobestats.io,AD-BAN
  - DOMAIN,9lbrsj3eqc.adobestats.io,AD-BAN
  - DOMAIN,bn4i1jgarl.adobestats.io,AD-BAN
  - DOMAIN,dio7fli6oc.adobestats.io,AD-BAN
  - DOMAIN,e4xy0my9e4.adobestats.io,AD-BAN
  - DOMAIN,ol8cco0yne.adobestats.io,AD-BAN
  - DOMAIN,p8seks0alh.adobestats.io,AD-BAN
  - DOMAIN,pf2jezndie.adobestats.io,AD-BAN
  - DOMAIN,tbo1621jaj.adobestats.io,AD-BAN
  - DOMAIN,yf9inv4f4a.adobestats.io,AD-BAN
  - DOMAIN,46si8xsrd4.adobestats.io,AD-BAN
  - DOMAIN,gxxj3ht33q.adobestats.io,AD-BAN
  - DOMAIN,ry5dhsrn9q.adobestats.io,AD-BAN
  - DOMAIN,4anjyeritg.adobestats.io,AD-BAN
  - DOMAIN,7tt98n5vr9.adobestats.io,AD-BAN
  - DOMAIN,k6bbumjg3j.adobestats.io,AD-BAN
  - DOMAIN,s7hxmji3fg.adobestats.io,AD-BAN
  - DOMAIN,w7wnvpf6it.adobestats.io,AD-BAN
  - DOMAIN,85zgeugwrx.adobestats.io,AD-BAN
  - DOMAIN,mbya1atovd.adobestats.io,AD-BAN
  - DOMAIN,2q9nqd24at.adobestats.io,AD-BAN
  - DOMAIN,bfe030zu1d.adobestats.io,AD-BAN
  - DOMAIN,bgu5bafji4.adobestats.io,AD-BAN
  - DOMAIN,canp69iyvw.adobestats.io,AD-BAN
  - DOMAIN,d5qylk77uu.adobestats.io,AD-BAN
  - DOMAIN,j0o3f8hx58.adobestats.io,AD-BAN
  - DOMAIN,m9320z1xwy.adobestats.io,AD-BAN
  - DOMAIN,srqwgyza90.adobestats.io,AD-BAN
  - DOMAIN,4e0e132d50.adobestats.io,AD-BAN
  - DOMAIN,7hy5neh7yd.adobestats.io,AD-BAN
  - DOMAIN,7up2et2elb.adobestats.io,AD-BAN
  - DOMAIN,8u23q07fai.adobestats.io,AD-BAN
  - DOMAIN,a4o6j6a60q.adobestats.io,AD-BAN
  - DOMAIN,cj75c7xu81.adobestats.io,AD-BAN
  - DOMAIN,ephqb5mlx2.adobestats.io,AD-BAN
  - DOMAIN,lc990on4y4.adobestats.io,AD-BAN
  - DOMAIN,lma74hsgmt.adobestats.io,AD-BAN
  - DOMAIN,oxebixf9bp.adobestats.io,AD-BAN
  - DOMAIN,pznf2cvokl.adobestats.io,AD-BAN
  - DOMAIN,v06zqmu5pk.adobestats.io,AD-BAN
  - DOMAIN,7cl578y97h.adobestats.io,AD-BAN
  - DOMAIN,8vf1533hg0.adobestats.io,AD-BAN
  - DOMAIN,j065cjonho.adobestats.io,AD-BAN
  - DOMAIN,gkuhot62li.adobestats.io,AD-BAN
  - DOMAIN,3jxakfyart.adobestats.io,AD-BAN
  - DOMAIN,eilhhpyrhk.adobestats.io,AD-BAN
  - DOMAIN,fi07tozbmh.adobestats.io,AD-BAN
  - DOMAIN,int03thy3s.adobestats.io,AD-BAN
  - DOMAIN,sk3nb074wt.adobestats.io,AD-BAN
  - DOMAIN,k5hez87wo3.adobestats.io,AD-BAN
  - DOMAIN,z8bpa11zz5.adobestats.io,AD-BAN
  - DOMAIN,op6ya9mf18.adobestats.io,AD-BAN
  - DOMAIN,p9jaddiqux.adobe.io,AD-BAN
  - DOMAIN,0mgqdi537f.adobestats.io,AD-BAN
  - DOMAIN,224me58l5q.adobestats.io,AD-BAN
  - DOMAIN,37ng6po6bp.adobestats.io,AD-BAN
  - DOMAIN,8mt9obctot.adobestats.io,AD-BAN
  - DOMAIN,aen6torhir.adobestats.io,AD-BAN
  - DOMAIN,dnqofyouwm.adobestats.io,AD-BAN
  - DOMAIN,h1sp8k6bhv.adobestats.io,AD-BAN
  - DOMAIN,hnebe5wyyy.adobestats.io,AD-BAN
  - DOMAIN,s8cxczmvh5.adobestats.io,AD-BAN
  - DOMAIN,v7yl9ajfg9.adobestats.io,AD-BAN
  - DOMAIN,wvfhx4enq4.adobestats.io,AD-BAN
  - DOMAIN,1s0s64nq7w.adobestats.io,AD-BAN
  - DOMAIN,9uxtpeji2v.adobestats.io,AD-BAN
  - DOMAIN,be4jspokx2.adobestats.io,AD-BAN
  - DOMAIN,r7x9tbvsvx.adobestats.io,AD-BAN
  - DOMAIN,w20hk05cgp.adobestats.io,AD-BAN
  - DOMAIN,x915sjr4n9.adobestats.io,AD-BAN
  - DOMAIN,xoq8wwlhsp.adobestats.io,AD-BAN
  - DOMAIN,64a4g05fmn.adobestats.io,AD-BAN
  - DOMAIN,6j5lc5swyh.adobestats.io,AD-BAN
  - DOMAIN,xwr6ju22ai.adobestats.io,AD-BAN
  - DOMAIN,1o54s13pxf.adobestats.io,AD-BAN
  - DOMAIN,4ypokgsgmb.adobestats.io,AD-BAN
  - DOMAIN,dvndpazg45.adobestats.io,AD-BAN
  - DOMAIN,eyp31zax99.adobestats.io,AD-BAN
  - DOMAIN,g059w52e5a.adobestats.io,AD-BAN
  - DOMAIN,p9t0tf8p73.adobestats.io,AD-BAN
  - DOMAIN,vyso4gf2fo.adobestats.io,AD-BAN
  - DOMAIN,ytm4prvsic.adobestats.io,AD-BAN
  - DOMAIN,3yx324cjrc.adobestats.io,AD-BAN
  - DOMAIN,zarflqrb4e.adobestats.io,AD-BAN
  - DOMAIN,u8dy2x6ofx.adobestats.io,AD-BAN
  - DOMAIN,d9u8iw3ec6.adobestats.io,AD-BAN
  - DOMAIN,8ksw9jeglo.adobestats.io,AD-BAN
  - DOMAIN,av91c4swlr.adobestats.io,AD-BAN
  - DOMAIN,nhijoow8u9.adobestats.io,AD-BAN
  - DOMAIN,ukl1tj2nvv.adobestats.io,AD-BAN
  - DOMAIN,w76a6nm3fs.adobestats.io,AD-BAN
  - DOMAIN,2uzp2kpn5r.adobestats.io,AD-BAN
  - DOMAIN,309q77jr8y.adobestats.io,AD-BAN
  - DOMAIN,3cb9jccasz.adobestats.io,AD-BAN
  - DOMAIN,3t80jr3icl.adobestats.io,AD-BAN
  - DOMAIN,46w37ofmyh.adobestats.io,AD-BAN
  - DOMAIN,4br2ud69pv.adobestats.io,AD-BAN
  - DOMAIN,8qq1w94u66.adobestats.io,AD-BAN
  - DOMAIN,fnx5ng6n5k.adobestats.io,AD-BAN
  - DOMAIN,je7b0l8vdo.adobestats.io,AD-BAN
  - DOMAIN,l7imn8j82x.adobestats.io,AD-BAN
  - DOMAIN,mbiowykjov.adobestats.io,AD-BAN
  - DOMAIN,oc64zoqehy.adobestats.io,AD-BAN
  - DOMAIN,r97n5i4gui.adobestats.io,AD-BAN
  - DOMAIN,sn7ul2kyne.adobestats.io,AD-BAN
  - DOMAIN,tz8aenh3nl.adobestats.io,AD-BAN
  - DOMAIN,bv7iaks1q0.adobestats.io,AD-BAN
  - DOMAIN,lmy2aip7t9.adobestats.io,AD-BAN
  - DOMAIN,v1p7zr510j.adobestats.io,AD-BAN
  - DOMAIN,aw725q3eth.adobestats.io,AD-BAN
  - DOMAIN,ltnk9caeyt.adobestats.io,AD-BAN
  - DOMAIN,ykcaj6bh15.adobestats.io,AD-BAN
  - DOMAIN,9ohyfdvj27.adobestats.io,AD-BAN
  - DOMAIN,lmvu17gkya.adobestats.io,AD-BAN
  - DOMAIN,0np4eiuov7.adobestats.io,AD-BAN
  - DOMAIN,6u32mwnaxq.adobestats.io,AD-BAN
  - DOMAIN,d3my5g4jna.adobestats.io,AD-BAN
  - DOMAIN,j8iepl91av.adobestats.io,AD-BAN
  - DOMAIN,no8yw4nh6e.adobestats.io,AD-BAN
  - DOMAIN,nop4h5fp61.adobestats.io,AD-BAN
  - DOMAIN,wvwrj2y0li.adobestats.io,AD-BAN
  - DOMAIN,zxv4wvfvi9.adobestats.io,AD-BAN
  - DOMAIN,2oyz2t4wq9.adobestats.io,AD-BAN
  - DOMAIN,5xnbj0m6t2.adobestats.io,AD-BAN
  - DOMAIN,6asnsetik3.adobestats.io,AD-BAN
  - DOMAIN,hknkvizuc2.adobestats.io,AD-BAN
  - DOMAIN,w8s4afl50t.adobestats.io,AD-BAN
  - DOMAIN,xaggdolnhv.adobestats.io,AD-BAN
  - DOMAIN,0nx23dhzap.adobestats.io,AD-BAN
  - DOMAIN,744jei1415.adobestats.io,AD-BAN
  - DOMAIN,ahuu2xu1ya.adobestats.io,AD-BAN
  - DOMAIN,al76al5u4u.adobestats.io,AD-BAN
  - DOMAIN,fq8re9lavq.adobestats.io,AD-BAN
  - DOMAIN,m38l9rfnry.adobestats.io,AD-BAN
  - DOMAIN,uzantvo0as.adobe.io,AD-BAN
  - DOMAIN,7gag9ygrcx.adobestats.io,AD-BAN
  - DOMAIN,7jg7m1ces4.adobestats.io,AD-BAN
  - DOMAIN,kk0sjamt88.adobestats.io,AD-BAN
  - DOMAIN,xygpp0qk24.adobestats.io,AD-BAN
  - DOMAIN,1kez8509ag.adobestats.io,AD-BAN
  - DOMAIN,ja7czxetms.adobestats.io,AD-BAN
  - DOMAIN,xldcvdx24q.adobestats.io,AD-BAN
  - DOMAIN,f03ibhcdnc.adobestats.io,AD-BAN
  - DOMAIN,cbfqosfuqi.adobestats.io,AD-BAN
  - DOMAIN,f95w5c40ys.adobestats.io,AD-BAN
  - DOMAIN,6mfhu1z5u7.adobestats.io,AD-BAN
  - DOMAIN,b360ay92q3.adobestats.io,AD-BAN
  - DOMAIN,xmmg8xhkjb.adobestats.io,AD-BAN
  - DOMAIN,it86bgy8qf.adobestats.io,AD-BAN
  - DOMAIN,ecsdxf3wl3.adobestats.io,AD-BAN
  - DOMAIN,3ivg7wus63.adobestats.io,AD-BAN
  - DOMAIN,nqnnfmo9od.adobestats.io,AD-BAN
  - DOMAIN,08g6cm4kaq.adobestats.io,AD-BAN
  - DOMAIN,32gijtiveo.adobestats.io,AD-BAN
  - DOMAIN,7i8vjvlwuc.adobestats.io,AD-BAN
  - DOMAIN,8bm7q3s69i.adobestats.io,AD-BAN
  - DOMAIN,9lz057fho1.adobestats.io,AD-BAN
  - DOMAIN,9oyru5uulx.adobestats.io,AD-BAN
  - DOMAIN,dwv18zn96z.adobestats.io,AD-BAN
  - DOMAIN,faag4y3x73.adobestats.io,AD-BAN
  - DOMAIN,jtc0fjhor2.adobestats.io,AD-BAN
  - DOMAIN,mkzec8b0pu.adobestats.io,AD-BAN
  - DOMAIN,nv8ysttp93.adobestats.io,AD-BAN
  - DOMAIN,rp9pax976k.adobestats.io,AD-BAN
  - DOMAIN,tzd44dufds.adobestats.io,AD-BAN
  - DOMAIN,w1tw8nuikr.adobestats.io,AD-BAN
  - DOMAIN,wdk81mqjw2.adobestats.io,AD-BAN
  - DOMAIN,xu0fl2f2fa.adobestats.io,AD-BAN
  - DOMAIN,fel2ajqj6q.adobestats.io,AD-BAN
  - DOMAIN,szlpwlqsj9.adobestats.io,AD-BAN
  - DOMAIN,1yqnqu95vt.adobestats.io,AD-BAN
  - DOMAIN,2drlj3q5q9.adobestats.io,AD-BAN
  - DOMAIN,6c2odkl2f7.adobestats.io,AD-BAN
  - DOMAIN,dzx1z8to3i.adobestats.io,AD-BAN
  - DOMAIN,8xi6eh0lbe.adobestats.io,AD-BAN
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,SELECT`
}



	
function getsbConfig(Pswd, hostName) {
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
			"address": "tls:
			"detour": "select"
		  },
		  {
			"tag": "localdns",
			"address": "h3:
			"detour": "direct"
		  },
		  {
			"address": "rcode:
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
        "CF_T1_${IP1}_${PT1}",
        "CF_T2_${IP2}_${PT2}",
        "CF_T3_${IP3}_${PT3}",
        "CF_T4_${IP4}_${PT4}",
        "CF_T5_${IP5}_${PT5}",
        "CF_T6_${IP6}_${PT6}",
        "CF_T7_${IP7}_${PT7}",
        "CF_T8_${IP8}_${PT8}",
        "CF_T9_${IP9}_${PT9}",
        "CF_T10_${IP10}_${PT10}",
        "CF_T11_${IP11}_${PT11}",
        "CF_T12_${IP12}_${PT12}",
        "CF_T13_${IP13}_${PT13}"
        ]
      },
      {
        "server": "${IP1}",
        "server_port": ${PT1},
        "tag": "CF_T1_${IP1}_${PT1}",
        "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          }, 
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {
        "server": "${IP2}",
        "server_port": ${PT2},
        "tag": "CF_T2_${IP2}_${PT2}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {
        "server": "${IP3}",
        "server_port": ${PT3},
        "tag": "CF_T3_${IP3}_${PT3}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {
        "server": "${IP4}",
        "server_port": ${PT4},
        "tag": "CF_T4_${IP4}_${PT4}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {
        "server": "${IP5}",
        "server_port": ${PT5},
        "tag": "CF_T5_${IP5}_${PT5}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {
        "server": "${IP6}",
        "server_port": ${PT6},
        "tag": "CF_T6_${IP6}_${PT6}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {
        "server": "${IP7}",
        "server_port": ${PT7},
        "tag": "CF_T7_${IP7}_${PT7}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {
        "server": "${IP8}",
        "server_port": ${PT8},
        "tag": "CF_T8_${IP8}_${PT8}",
        "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
        "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {     
        "server": "${IP9}",
        "server_port": ${PT9},
        "tag": "CF_T9_${IP9}_${PT9}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {     
        "server": "${IP10}",
        "server_port": ${PT10},
        "tag": "CF_T10_${IP10}_${PT10}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {     
        "server": "${IP11}",
        "server_port": ${PT11},
        "tag": "CF_T11_${IP11}_${PT11}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {
        "server": "${IP12}",
        "server_port": ${PT12},
        "tag": "CF_T12_${IP12}_${PT12}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
      },
      {     
        "server": "${IP13}",
        "server_port": ${PT13},
        "tag": "CF_T13_${IP13}_${PT13}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "trojan",
        "password": "${Pswd}"
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
        "CF_T1_${IP1}_${PT1}",
        "CF_T2_${IP2}_${PT2}",
        "CF_T3_${IP3}_${PT3}",
        "CF_T4_${IP4}_${PT4}",
        "CF_T5_${IP5}_${PT5}",
        "CF_T6_${IP6}_${PT6}",
        "CF_T7_${IP7}_${PT7}",
        "CF_T8_${IP8}_${PT8}",
        "CF_T9_${IP9}_${PT9}",
        "CF_T10_${IP10}_${PT10}",
        "CF_T11_${IP11}_${PT11}",
        "CF_T12_${IP12}_${PT12}",
        "CF_T13_${IP13}_${PT13}"
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

function getptyConfig(Pswd, hostName) {
  const trojanshare = btoa(`trojan://${Pswd}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T8_${IP8}_${PT8}\ntrojan://${Pswd}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T9_${IP9}_${PT9}\ntrojan://${Pswd}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T10_${IP10}_${PT10}\ntrojan://${Pswd}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T11_${IP11}_${PT11}\ntrojan://${Pswd}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T12_${IP12}_${PT12}\ntrojan://${Pswd}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T13_${IP13}_${PT13}`);
  return `${trojanshare}`
}
	
function getpclConfig(Pswd, hostName) {
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
- name: CF_T8_${IP8}_${PT8}
  type: trojan
  server: ${IP8}
  port: ${PT8}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T9_${IP9}_${PT9}
  type: trojan
  server: ${IP9}
  port: ${PT9}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T10_${IP10}_${PT10}
  type: trojan
  server: ${IP10}
  port: ${PT10}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T11_${IP11}_${PT11}
  type: trojan
  server: ${IP11}
  port: ${PT11}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T12_${IP12}_${PT12}
  type: trojan
  server: ${IP12}
  port: ${PT12}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T13_${IP13}_${PT13}
  type: trojan
  server: ${IP13}
  port: ${PT13}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: LAX1
  type: trojan
  server: 104.21.198.62
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: LAX2
  type: trojan
  server: 162.159.45.219
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: HKG1
  type: trojan
  server: 104.20.206.24
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: AMS
  type: trojan
  server: 162.159.160.204
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: LHR
  type: trojan
  server: 162.159.81.154
  port: 2096
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: TW
  type: trojan
  server: 210.61.97.241
  port: 81
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: LOAD
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}
    - LAX1
    - LAX2
    - HKG1
    - AMS
    - LHR
    - TW

- name: AUTO
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}
    - LAX1
    - LAX2
    - HKG1
    - AMS
    - LHR
    - TW

- name: SELECT
  type: select
  proxies:
    - LOAD
    - AUTO
    - DIRECT
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}
    - LAX1
    - LAX2
    - HKG1
    - AMS
    - LHR
    - TW

- name: BILI
  type: select
  url: https://www.bilibili.com/
  proxies:
    - DIRECT
    - SELECT
    - HKG1
    - TW

- name: DC
  type: select
  proxies:
    - DIRECT
    - AUTO
    - SELECT

- name: AD-BAN
  type: select
  proxies:
    - REJECT
    - DIRECT

rules:
  - PROCESS-NAME,cfnat-android-arm64,DC
  - PROCESS-NAME,cfnat-darwin-amd64,DC
  - PROCESS-NAME,cfnat-darwin-arm64,DC
  - PROCESS-NAME,cfnat-dragonfly-amd64,DC
  - PROCESS-NAME,cfnat-freebsd-386,DC
  - PROCESS-NAME,cfnat-freebsd-amd64,DC
  - PROCESS-NAME,cfnat-freebsd-arm,DC
  - PROCESS-NAME,cfnat-freebsd-arm64,DC
  - PROCESS-NAME,cfnat-linux-386,DC
  - PROCESS-NAME,cfnat-linux-amd64,DC
  - PROCESS-NAME,cfnat-linux-arm,DC
  - PROCESS-NAME,cfnat-linux-arm64,DC
  - PROCESS-NAME,cfnat-linux-mips,DC
  - PROCESS-NAME,cfnat-linux-mips64,DC
  - PROCESS-NAME,cfnat-linux-mips64le,DC
  - PROCESS-NAME,cfnat-linux-mipsle,DC
  - PROCESS-NAME,cfnat-linux-ppc64,DC
  - PROCESS-NAME,cfnat-linux-ppc64le,DC
  - PROCESS-NAME,cfnat-linux-riscv64,DC
  - PROCESS-NAME,cfnat-linux-s390x,DC
  - PROCESS-NAME,cfnat-netbsd-386,DC
  - PROCESS-NAME,cfnat-netbsd-amd64,DC
  - PROCESS-NAME,cfnat-netbsd-arm,DC
  - PROCESS-NAME,cfnat-netbsd-arm64,DC
  - PROCESS-NAME,cfnat-openbsd-386,DC
  - PROCESS-NAME,cfnat-openbsd-amd64,DC
  - PROCESS-NAME,cfnat-openbsd-arm,DC
  - PROCESS-NAME,cfnat-openbsd-arm64,DC
  - PROCESS-NAME,cfnat-plan9-386,DC
  - PROCESS-NAME,cfnat-plan9-amd64,DC
  - PROCESS-NAME,cfnat-solaris-amd64,DC
  - PROCESS-NAME,cfnat-termux,DC
  - PROCESS-NAME,cfnat-windows-386.exe,DC
  - PROCESS-NAME,cfnat-windows-amd64.exe,DC
  - PROCESS-NAME,cfnat-windows-arm.exe,DC
  - PROCESS-NAME,cfnat-windows-arm64.exe,DC
  - PROCESS-NAME,cfnat-windows7-386.exe,DC
  - PROCESS-NAME,cfnat-windows7-amd64.exe,DC
  - PROCESS-NAME,colo-android-arm64,DC
  - PROCESS-NAME,colo-darwin-amd64,DC
  - PROCESS-NAME,colo-darwin-arm64,DC
  - PROCESS-NAME,colo-dragonfly-amd64,DC
  - PROCESS-NAME,colo-freebsd-386,DC
  - PROCESS-NAME,colo-freebsd-amd64,DC
  - PROCESS-NAME,colo-freebsd-arm,DC
  - PROCESS-NAME,colo-freebsd-arm64,DC
  - PROCESS-NAME,colo-linux-386,DC
  - PROCESS-NAME,colo-linux-amd64,DC
  - PROCESS-NAME,colo-linux-arm,DC
  - PROCESS-NAME,colo-linux-arm64,DC
  - PROCESS-NAME,colo-linux-mips,DC
  - PROCESS-NAME,colo-linux-mips64,DC
  - PROCESS-NAME,colo-linux-mips64le,DC
  - PROCESS-NAME,colo-linux-mipsle,DC
  - PROCESS-NAME,colo-linux-ppc64,DC
  - PROCESS-NAME,colo-linux-ppc64le,DC
  - PROCESS-NAME,colo-linux-riscv64,DC
  - PROCESS-NAME,colo-linux-s390x,DC
  - PROCESS-NAME,colo-netbsd-386,DC
  - PROCESS-NAME,colo-netbsd-amd64,DC
  - PROCESS-NAME,colo-netbsd-arm,DC
  - PROCESS-NAME,colo-netbsd-arm64,DC
  - PROCESS-NAME,colo-openbsd-386,DC
  - PROCESS-NAME,colo-openbsd-amd64,DC
  - PROCESS-NAME,colo-openbsd-arm,DC
  - PROCESS-NAME,colo-openbsd-arm64,DC
  - PROCESS-NAME,colo-plan9-386,DC
  - PROCESS-NAME,colo-plan9-amd64,DC
  - PROCESS-NAME,colo-solaris-amd64,DC
  - PROCESS-NAME,colo-windows-386.exe,DC
  - PROCESS-NAME,colo-windows-amd64.exe,DC
  - PROCESS-NAME,colo-windows-arm.exe,DC
  - PROCESS-NAME,colo-windows-arm64.exe,DC
  - DOMAIN-SUFFIX,acl4.ssr,DC
  - DOMAIN-SUFFIX,ip6-localhost,DC
  - DOMAIN-SUFFIX,ip6-loopback,DC
  - DOMAIN-SUFFIX,lan,DC
  - DOMAIN-SUFFIX,local,DC
  - DOMAIN-SUFFIX,localhost,DC
  - IP-CIDR,0.0.0.0/8,DC,no-resolve
  - IP-CIDR,10.0.0.0/8,DC,no-resolve
  - IP-CIDR,100.64.0.0/10,DC,no-resolve
  - IP-CIDR,127.0.0.0/8,DC,no-resolve
  - IP-CIDR,172.16.0.0/12,DC,no-resolve
  - IP-CIDR,192.168.0.0/16,DC,no-resolve
  - IP-CIDR,198.18.0.0/16,DC,no-resolve
  - IP-CIDR,224.0.0.0/4,DC,no-resolve
  - IP-CIDR6,::1/128,DC,no-resolve
  - IP-CIDR6,fc00::/7,DC,no-resolve
  - IP-CIDR6,fe80::/10,DC,no-resolve
  - IP-CIDR6,fd00::/8,DC,no-resolve
  - DOMAIN,instant.arubanetworks.com,DC
  - DOMAIN,setmeup.arubanetworks.com,DC
  - DOMAIN,router.asus.com,DC
  - DOMAIN,www.asusrouter.com,DC
  - DOMAIN-SUFFIX,hiwifi.com,DC
  - DOMAIN-SUFFIX,leike.cc,DC
  - DOMAIN-SUFFIX,miwifi.com,DC
  - DOMAIN-SUFFIX,my.router,DC
  - DOMAIN-SUFFIX,p.to,DC
  - DOMAIN-SUFFIX,peiluyou.com,DC
  - DOMAIN-SUFFIX,phicomm.me,DC
  - DOMAIN-SUFFIX,router.ctc,DC
  - DOMAIN-SUFFIX,routerlogin.com,DC
  - DOMAIN-SUFFIX,tendawifi.com,DC
  - DOMAIN-SUFFIX,zte.home,DC
  - DOMAIN-SUFFIX,tplogin.cn,DC
  - DOMAIN-SUFFIX,wifi.cmcc,DC
  - DOMAIN-SUFFIX,ol.epicgames.com,DC
  - DOMAIN-SUFFIX,dizhensubao.getui.com,DC
  - DOMAIN,dl.google.com,DC
  - DOMAIN-SUFFIX,googletraveladservices.com,DC
  - DOMAIN-SUFFIX,tracking-protection.cdn.mozilla.net,DC
  - DOMAIN,origin-a.akamaihd.net,DC
  - DOMAIN,fairplay.l.qq.com,DC
  - DOMAIN,livew.l.qq.com,DC
  - DOMAIN,vd.l.qq.com,DC
  - DOMAIN,errlog.umeng.com,DC
  - DOMAIN,msg.umeng.com,DC
  - DOMAIN,msg.umengcloud.com,DC
  - DOMAIN,tracking.miui.com,DC
  - DOMAIN,app.adjust.com,DC
  - DOMAIN,bdtj.tagtic.cn,DC
  - DOMAIN,rewards.hypixel.net,DC
  - DOMAIN-SUFFIX,koodomobile.com,DC
  - DOMAIN-SUFFIX,koodomobile.ca,DC
  - DOMAIN-KEYWORD,admarvel,AD-BAN
  - DOMAIN-KEYWORD,admaster,AD-BAN
  - DOMAIN-KEYWORD,adsage,AD-BAN
  - DOMAIN-KEYWORD,adsensor,AD-BAN
  - DOMAIN-KEYWORD,adsmogo,AD-BAN
  - DOMAIN-KEYWORD,adsrvmedia,AD-BAN
  - DOMAIN-KEYWORD,adsserving,AD-BAN
  - DOMAIN-KEYWORD,adsystem,AD-BAN
  - DOMAIN-KEYWORD,adwords,AD-BAN
  - DOMAIN-KEYWORD,applovin,AD-BAN
  - DOMAIN-KEYWORD,appsflyer,AD-BAN
  - DOMAIN-KEYWORD,domob,AD-BAN
  - DOMAIN-KEYWORD,duomeng,AD-BAN
  - DOMAIN-KEYWORD,dwtrack,AD-BAN
  - DOMAIN-KEYWORD,guanggao,AD-BAN
  - DOMAIN-KEYWORD,omgmta,AD-BAN
  - DOMAIN-KEYWORD,omniture,AD-BAN
  - DOMAIN-KEYWORD,openx,AD-BAN
  - DOMAIN-KEYWORD,partnerad,AD-BAN
  - DOMAIN-KEYWORD,pingfore,AD-BAN
  - DOMAIN-KEYWORD,socdm,AD-BAN
  - DOMAIN-KEYWORD,supersonicads,AD-BAN
  - DOMAIN-KEYWORD,wlmonitor,AD-BAN
  - DOMAIN-KEYWORD,zjtoolbar,AD-BAN
  - DOMAIN-SUFFIX,09mk.cn,AD-BAN
  - DOMAIN-SUFFIX,100peng.com,AD-BAN
  - DOMAIN-SUFFIX,114la.com,AD-BAN
  - DOMAIN-SUFFIX,123juzi.net,AD-BAN
  - DOMAIN-SUFFIX,138lm.com,AD-BAN
  - DOMAIN-SUFFIX,17un.com,AD-BAN
  - DOMAIN-SUFFIX,2cnt.net,AD-BAN
  - DOMAIN-SUFFIX,3gmimo.com,AD-BAN
  - DOMAIN-SUFFIX,3xx.vip,AD-BAN
  - DOMAIN-SUFFIX,51.la,AD-BAN
  - DOMAIN-SUFFIX,51taifu.com,AD-BAN
  - DOMAIN-SUFFIX,51yes.com,AD-BAN
  - DOMAIN-SUFFIX,600ad.com,AD-BAN
  - DOMAIN-SUFFIX,6dad.com,AD-BAN
  - DOMAIN-SUFFIX,70e.com,AD-BAN
  - DOMAIN-SUFFIX,86.cc,AD-BAN
  - DOMAIN-SUFFIX,8le8le.com,AD-BAN
  - DOMAIN-SUFFIX,8ox.cn,AD-BAN
  - DOMAIN-SUFFIX,95558000.com,AD-BAN
  - DOMAIN-SUFFIX,99click.com,AD-BAN
  - DOMAIN-SUFFIX,99youmeng.com,AD-BAN
  - DOMAIN-SUFFIX,a3p4.net,AD-BAN
  - DOMAIN-SUFFIX,acs86.com,AD-BAN
  - DOMAIN-SUFFIX,acxiom-online.com,AD-BAN
  - DOMAIN-SUFFIX,ad-brix.com,AD-BAN
  - DOMAIN-SUFFIX,ad-delivery.net,AD-BAN
  - DOMAIN-SUFFIX,ad-locus.com,AD-BAN
  - DOMAIN-SUFFIX,ad-plus.cn,AD-BAN
  - DOMAIN-SUFFIX,ad7.com,AD-BAN
  - DOMAIN-SUFFIX,adadapted.com,AD-BAN
  - DOMAIN-SUFFIX,adadvisor.net,AD-BAN
  - DOMAIN-SUFFIX,adap.tv,AD-BAN
  - DOMAIN-SUFFIX,adbana.com,AD-BAN
  - DOMAIN-SUFFIX,adchina.com,AD-BAN
  - DOMAIN-SUFFIX,adcome.cn,AD-BAN
  - DOMAIN-SUFFIX,ader.mobi,AD-BAN
  - DOMAIN-SUFFIX,adform.net,AD-BAN
  - DOMAIN-SUFFIX,adfuture.cn,AD-BAN
  - DOMAIN-SUFFIX,adhouyi.com,AD-BAN
  - DOMAIN-SUFFIX,adinfuse.com,AD-BAN
  - DOMAIN-SUFFIX,adirects.com,AD-BAN
  - DOMAIN-SUFFIX,adjust.io,AD-BAN
  - DOMAIN-SUFFIX,adkmob.com,AD-BAN
  - DOMAIN-SUFFIX,adlive.cn,AD-BAN
  - DOMAIN-SUFFIX,adlocus.com,AD-BAN
  - DOMAIN-SUFFIX,admaji.com,AD-BAN
  - DOMAIN-SUFFIX,admin6.com,AD-BAN
  - DOMAIN-SUFFIX,admon.cn,AD-BAN
  - DOMAIN-SUFFIX,adnyg.com,AD-BAN
  - DOMAIN-SUFFIX,adpolestar.net,AD-BAN
  - DOMAIN-SUFFIX,adpro.cn,AD-BAN
  - DOMAIN-SUFFIX,adpush.cn,AD-BAN
  - DOMAIN-SUFFIX,adquan.com,AD-BAN
  - DOMAIN-SUFFIX,adreal.cn,AD-BAN
  - DOMAIN-SUFFIX,ads8.com,AD-BAN
  - DOMAIN-SUFFIX,adsame.com,AD-BAN
  - DOMAIN-SUFFIX,adsmogo.com,AD-BAN
  - DOMAIN-SUFFIX,adsmogo.org,AD-BAN
  - DOMAIN-SUFFIX,adsunflower.com,AD-BAN
  - DOMAIN-SUFFIX,adsunion.com,AD-BAN
  - DOMAIN-SUFFIX,adtrk.me,AD-BAN
  - DOMAIN-SUFFIX,adups.com,AD-BAN
  - DOMAIN-SUFFIX,aduu.cn,AD-BAN
  - DOMAIN-SUFFIX,advertising.com,AD-BAN
  - DOMAIN-SUFFIX,adview.cn,AD-BAN
  - DOMAIN-SUFFIX,advmob.cn,AD-BAN
  - DOMAIN-SUFFIX,adwetec.com,AD-BAN
  - DOMAIN-SUFFIX,adwhirl.com,AD-BAN
  - DOMAIN-SUFFIX,adwo.com,AD-BAN
  - DOMAIN-SUFFIX,adxmi.com,AD-BAN
  - DOMAIN-SUFFIX,adyun.com,AD-BAN
  - DOMAIN-SUFFIX,adzerk.net,AD-BAN
  - DOMAIN-SUFFIX,agrant.cn,AD-BAN
  - DOMAIN-SUFFIX,agrantsem.com,AD-BAN
  - DOMAIN-SUFFIX,aihaoduo.cn,AD-BAN
  - DOMAIN-SUFFIX,ajapk.com,AD-BAN
  - DOMAIN-SUFFIX,allyes.cn,AD-BAN
  - DOMAIN-SUFFIX,allyes.com,AD-BAN
  - DOMAIN-SUFFIX,amazon-adsystem.com,AD-BAN
  - DOMAIN-SUFFIX,analysys.cn,AD-BAN
  - DOMAIN-SUFFIX,angsrvr.com,AD-BAN
  - DOMAIN-SUFFIX,anquan.org,AD-BAN
  - DOMAIN-SUFFIX,anysdk.com,AD-BAN
  - DOMAIN-SUFFIX,appadhoc.com,AD-BAN
  - DOMAIN-SUFFIX,appads.com,AD-BAN
  - DOMAIN-SUFFIX,appboy.com,AD-BAN
  - DOMAIN-SUFFIX,appdriver.cn,AD-BAN
  - DOMAIN-SUFFIX,appjiagu.com,AD-BAN
  - DOMAIN-SUFFIX,applifier.com,AD-BAN
  - DOMAIN-SUFFIX,appsflyer.com,AD-BAN
  - DOMAIN-SUFFIX,atdmt.com,AD-BAN
  - DOMAIN-SUFFIX,baifendian.com,AD-BAN
  - DOMAIN-SUFFIX,banmamedia.com,AD-BAN
  - DOMAIN-SUFFIX,baoyatu.cc,AD-BAN
  - DOMAIN-SUFFIX,baycode.cn,AD-BAN
  - DOMAIN-SUFFIX,bayimob.com,AD-BAN
  - DOMAIN-SUFFIX,behe.com,AD-BAN
  - DOMAIN-SUFFIX,bfshan.cn,AD-BAN
  - DOMAIN-SUFFIX,biddingos.com,AD-BAN
  - DOMAIN-SUFFIX,biddingx.com,AD-BAN
  - DOMAIN-SUFFIX,bjvvqu.cn,AD-BAN
  - DOMAIN-SUFFIX,bjxiaohua.com,AD-BAN
  - DOMAIN-SUFFIX,bloggerads.net,AD-BAN
  - DOMAIN-SUFFIX,branch.io,AD-BAN
  - DOMAIN-SUFFIX,bsdev.cn,AD-BAN
  - DOMAIN-SUFFIX,bshare.cn,AD-BAN
  - DOMAIN-SUFFIX,btyou.com,AD-BAN
  - DOMAIN-SUFFIX,bugtags.com,AD-BAN
  - DOMAIN-SUFFIX,buysellads.com,AD-BAN
  - DOMAIN-SUFFIX,c0563.com,AD-BAN
  - DOMAIN-SUFFIX,cacafly.com,AD-BAN
  - DOMAIN-SUFFIX,casee.cn,AD-BAN
  - DOMAIN-SUFFIX,cdnmaster.com,AD-BAN
  - DOMAIN-SUFFIX,chance-ad.com,AD-BAN
  - DOMAIN-SUFFIX,chanet.com.cn,AD-BAN
  - DOMAIN-SUFFIX,chartbeat.com,AD-BAN
  - DOMAIN-SUFFIX,chartboost.com,AD-BAN
  - DOMAIN-SUFFIX,chengadx.com,AD-BAN
  - DOMAIN-SUFFIX,chmae.com,AD-BAN
  - DOMAIN-SUFFIX,clickadu.com,AD-BAN
  - DOMAIN-SUFFIX,clicki.cn,AD-BAN
  - DOMAIN-SUFFIX,clicktracks.com,AD-BAN
  - DOMAIN-SUFFIX,clickzs.com,AD-BAN
  - DOMAIN-SUFFIX,cloudmobi.net,AD-BAN
  - DOMAIN-SUFFIX,cmcore.com,AD-BAN
  - DOMAIN-SUFFIX,cnxad.com,AD-BAN
  - DOMAIN-SUFFIX,cnzz.com,AD-BAN
  - DOMAIN-SUFFIX,cnzzlink.com,AD-BAN
  - DOMAIN-SUFFIX,cocounion.com,AD-BAN
  - DOMAIN-SUFFIX,coocaatv.com,AD-BAN
  - DOMAIN-SUFFIX,cooguo.com,AD-BAN
  - DOMAIN-SUFFIX,coolguang.com,AD-BAN
  - DOMAIN-SUFFIX,coremetrics.com,AD-BAN
  - DOMAIN-SUFFIX,cpmchina.co,AD-BAN
  - DOMAIN-SUFFIX,cpx24.com,AD-BAN
  - DOMAIN-SUFFIX,crasheye.cn,AD-BAN
  - DOMAIN-SUFFIX,crosschannel.com,AD-BAN
  - DOMAIN-SUFFIX,ctrmi.com,AD-BAN
  - DOMAIN-SUFFIX,customer-security.online,AD-BAN
  - DOMAIN-SUFFIX,daoyoudao.com,AD-BAN
  - DOMAIN-SUFFIX,datouniao.com,AD-BAN
  - DOMAIN-SUFFIX,ddapp.cn,AD-BAN
  - DOMAIN-SUFFIX,dianjoy.com,AD-BAN
  - DOMAIN-SUFFIX,dianru.com,AD-BAN
  - DOMAIN-SUFFIX,disqusads.com,AD-BAN
  - DOMAIN-SUFFIX,domob.cn,AD-BAN
  - DOMAIN-SUFFIX,domob.com.cn,AD-BAN
  - DOMAIN-SUFFIX,domob.org,AD-BAN
  - DOMAIN-SUFFIX,dotmore.com.tw,AD-BAN
  - DOMAIN-SUFFIX,doubleverify.com,AD-BAN
  - DOMAIN-SUFFIX,doudouguo.com,AD-BAN
  - DOMAIN-SUFFIX,doumob.com,AD-BAN
  - DOMAIN-SUFFIX,duanat.com,AD-BAN
  - DOMAIN-SUFFIX,duiba.com.cn,AD-BAN
  - DOMAIN-SUFFIX,duomeng.cn,AD-BAN
  - DOMAIN-SUFFIX,dxpmedia.com,AD-BAN
  - DOMAIN-SUFFIX,edigitalsurvey.com,AD-BAN
  - DOMAIN-SUFFIX,eduancm.com,AD-BAN
  - DOMAIN-SUFFIX,emarbox.com,AD-BAN
  - DOMAIN-SUFFIX,exosrv.com,AD-BAN
  - DOMAIN-SUFFIX,fancyapi.com,AD-BAN
  - DOMAIN-SUFFIX,feitian001.com,AD-BAN
  - DOMAIN-SUFFIX,feixin2.com,AD-BAN
  - DOMAIN-SUFFIX,flashtalking.com,AD-BAN
  - DOMAIN-SUFFIX,fraudmetrix.cn,AD-BAN
  - DOMAIN-SUFFIX,g1.tagtic.cn,AD-BAN
  - DOMAIN-SUFFIX,gentags.net,AD-BAN
  - DOMAIN-SUFFIX,gepush.com,AD-BAN
  - DOMAIN-SUFFIX,getui.com,AD-BAN
  - DOMAIN-SUFFIX,glispa.com,AD-BAN
  - DOMAIN-SUFFIX,go-mpulse,AD-BAN
  - DOMAIN-SUFFIX,go-mpulse.net,AD-BAN
  - DOMAIN-SUFFIX,godloveme.cn,AD-BAN
  - DOMAIN-SUFFIX,gridsum.com,AD-BAN
  - DOMAIN-SUFFIX,gridsumdissector.cn,AD-BAN
  - DOMAIN-SUFFIX,gridsumdissector.com,AD-BAN
  - DOMAIN-SUFFIX,growingio.com,AD-BAN
  - DOMAIN-SUFFIX,guohead.com,AD-BAN
  - DOMAIN-SUFFIX,guomob.com,AD-BAN
  - DOMAIN-SUFFIX,haoghost.com,AD-BAN
  - DOMAIN-SUFFIX,hivecn.cn,AD-BAN
  - DOMAIN-SUFFIX,hypers.com,AD-BAN
  - DOMAIN-SUFFIX,icast.cn,AD-BAN
  - DOMAIN-SUFFIX,igexin.com,AD-BAN
  - DOMAIN-SUFFIX,il8r.com,AD-BAN
  - DOMAIN-SUFFIX,imageter.com,AD-BAN
  - DOMAIN-SUFFIX,immob.cn,AD-BAN
  - DOMAIN-SUFFIX,inad.com,AD-BAN
  - DOMAIN-SUFFIX,inmobi.cn,AD-BAN
  - DOMAIN-SUFFIX,inmobi.net,AD-BAN
  - DOMAIN-SUFFIX,inmobicdn.cn,AD-BAN
  - DOMAIN-SUFFIX,inmobicdn.net,AD-BAN
  - DOMAIN-SUFFIX,innity.com,AD-BAN
  - DOMAIN-SUFFIX,instabug.com,AD-BAN
  - DOMAIN-SUFFIX,intely.cn,AD-BAN
  - DOMAIN-SUFFIX,iperceptions.com,AD-BAN
  - DOMAIN-SUFFIX,ipinyou.com,AD-BAN
  - DOMAIN-SUFFIX,irs01.com,AD-BAN
  - DOMAIN-SUFFIX,irs01.net,AD-BAN
  - DOMAIN-SUFFIX,irs09.com,AD-BAN
  - DOMAIN-SUFFIX,istreamsche.com,AD-BAN
  - DOMAIN-SUFFIX,jesgoo.com,AD-BAN
  - DOMAIN-SUFFIX,jiaeasy.net,AD-BAN
  - DOMAIN-SUFFIX,jiguang.cn,AD-BAN
  - DOMAIN-SUFFIX,jimdo.com,AD-BAN
  - DOMAIN-SUFFIX,jisucn.com,AD-BAN
  - DOMAIN-SUFFIX,jmgehn.cn,AD-BAN
  - DOMAIN-SUFFIX,jpush.cn,AD-BAN
  - DOMAIN-SUFFIX,jusha.com,AD-BAN
  - DOMAIN-SUFFIX,juzi.cn,AD-BAN
  - DOMAIN-SUFFIX,juzilm.com,AD-BAN
  - DOMAIN-SUFFIX,kejet.com,AD-BAN
  - DOMAIN-SUFFIX,kejet.net,AD-BAN
  - DOMAIN-SUFFIX,keydot.net,AD-BAN
  - DOMAIN-SUFFIX,keyrun.cn,AD-BAN
  - DOMAIN-SUFFIX,kmd365.com,AD-BAN
  - DOMAIN-SUFFIX,krux.net,AD-BAN
  - DOMAIN-SUFFIX,lnk0.com,AD-BAN
  - DOMAIN-SUFFIX,lnk8.cn,AD-BAN
  - DOMAIN-SUFFIX,localytics.com,AD-BAN
  - DOMAIN-SUFFIX,lomark.cn,AD-BAN
  - DOMAIN-SUFFIX,lotuseed.com,AD-BAN
  - DOMAIN-SUFFIX,lrswl.com,AD-BAN
  - DOMAIN-SUFFIX,lufax.com,AD-BAN
  - DOMAIN-SUFFIX,madhouse.cn,AD-BAN
  - DOMAIN-SUFFIX,madmini.com,AD-BAN
  - DOMAIN-SUFFIX,madserving.com,AD-BAN
  - DOMAIN-SUFFIX,magicwindow.cn,AD-BAN
  - DOMAIN-SUFFIX,mathtag.com,AD-BAN
  - DOMAIN-SUFFIX,maysunmedia.com,AD-BAN
  - DOMAIN-SUFFIX,mbai.cn,AD-BAN
  - DOMAIN-SUFFIX,mediaplex.com,AD-BAN
  - DOMAIN-SUFFIX,mediav.com,AD-BAN
  - DOMAIN-SUFFIX,megajoy.com,AD-BAN
  - DOMAIN-SUFFIX,mgogo.com,AD-BAN
  - DOMAIN-SUFFIX,miaozhen.com,AD-BAN
  - DOMAIN-SUFFIX,microad-cn.com,AD-BAN
  - DOMAIN-SUFFIX,miidi.net,AD-BAN
  - DOMAIN-SUFFIX,mijifen.com,AD-BAN
  - DOMAIN-SUFFIX,mixpanel.com,AD-BAN
  - DOMAIN-SUFFIX,mjmobi.com,AD-BAN
  - DOMAIN-SUFFIX,mng-ads.com,AD-BAN
  - DOMAIN-SUFFIX,moad.cn,AD-BAN
  - DOMAIN-SUFFIX,moatads.com,AD-BAN
  - DOMAIN-SUFFIX,mobaders.com,AD-BAN
  - DOMAIN-SUFFIX,mobclix.com,AD-BAN
  - DOMAIN-SUFFIX,mobgi.com,AD-BAN
  - DOMAIN-SUFFIX,mobisage.cn,AD-BAN
  - DOMAIN-SUFFIX,mobvista.com,AD-BAN
  - DOMAIN-SUFFIX,moogos.com,AD-BAN
  - DOMAIN-SUFFIX,mopub.com,AD-BAN
  - DOMAIN-SUFFIX,moquanad.com,AD-BAN
  - DOMAIN-SUFFIX,mpush.cn,AD-BAN
  - DOMAIN-SUFFIX,mxpnl.com,AD-BAN
  - DOMAIN-SUFFIX,myhug.cn,AD-BAN
  - DOMAIN-SUFFIX,mzy2014.com,AD-BAN
  - DOMAIN-SUFFIX,networkbench.com,AD-BAN
  - DOMAIN-SUFFIX,ninebox.cn,AD-BAN
  - DOMAIN-SUFFIX,ntalker.com,AD-BAN
  - DOMAIN-SUFFIX,nylalobghyhirgh.com,AD-BAN
  - DOMAIN-SUFFIX,o2omobi.com,AD-BAN
  - DOMAIN-SUFFIX,oadz.com,AD-BAN
  - DOMAIN-SUFFIX,oneapm.com,AD-BAN
  - DOMAIN-SUFFIX,onetad.com,AD-BAN
  - DOMAIN-SUFFIX,optaim.com,AD-BAN
  - DOMAIN-SUFFIX,optimix.asia,AD-BAN
  - DOMAIN-SUFFIX,optimix.cn,AD-BAN
  - DOMAIN-SUFFIX,optimizelyapis.com,AD-BAN
  - DOMAIN-SUFFIX,overture.com,AD-BAN
  - DOMAIN-SUFFIX,p0y.cn,AD-BAN
  - DOMAIN-SUFFIX,pagechoice.net,AD-BAN
  - DOMAIN-SUFFIX,pingdom.net,AD-BAN
  - DOMAIN-SUFFIX,plugrush.com,AD-BAN
  - DOMAIN-SUFFIX,popin.cc,AD-BAN
  - DOMAIN-SUFFIX,pro.cn,AD-BAN
  - DOMAIN-SUFFIX,publicidad.net,AD-BAN
  - DOMAIN-SUFFIX,publicidad.tv,AD-BAN
  - DOMAIN-SUFFIX,pubmatic.com,AD-BAN
  - DOMAIN-SUFFIX,pubnub.com,AD-BAN
  - DOMAIN-SUFFIX,qcl777.com,AD-BAN
  - DOMAIN-SUFFIX,qiyou.com,AD-BAN
  - DOMAIN-SUFFIX,qtmojo.com,AD-BAN
  - DOMAIN-SUFFIX,quantcount.com,AD-BAN
  - DOMAIN-SUFFIX,qucaigg.com,AD-BAN
  - DOMAIN-SUFFIX,qumi.com,AD-BAN
  - DOMAIN-SUFFIX,qxxys.com,AD-BAN
  - DOMAIN-SUFFIX,reachmax.cn,AD-BAN
  - DOMAIN-SUFFIX,responsys.net,AD-BAN
  - DOMAIN-SUFFIX,revsci.net,AD-BAN
  - DOMAIN-SUFFIX,rlcdn.com,AD-BAN
  - DOMAIN-SUFFIX,rtbasia.com,AD-BAN
  - DOMAIN-SUFFIX,sanya1.com,AD-BAN
  - DOMAIN-SUFFIX,scupio.com,AD-BAN
  - DOMAIN-SUFFIX,shuiguo.com,AD-BAN
  - DOMAIN-SUFFIX,shuzilm.cn,AD-BAN
  - DOMAIN-SUFFIX,similarweb.com,AD-BAN
  - DOMAIN-SUFFIX,sitemeter.com,AD-BAN
  - DOMAIN-SUFFIX,sitescout.com,AD-BAN
  - DOMAIN-SUFFIX,sitetag.us,AD-BAN
  - DOMAIN-SUFFIX,smartmad.com,AD-BAN
  - DOMAIN-SUFFIX,social-touch.com,AD-BAN
  - DOMAIN-SUFFIX,somecoding.com,AD-BAN
  - DOMAIN-SUFFIX,sponsorpay.com,AD-BAN
  - DOMAIN-SUFFIX,stargame.com,AD-BAN
  - DOMAIN-SUFFIX,stg8.com,AD-BAN
  - DOMAIN-SUFFIX,switchadhub.com,AD-BAN
  - DOMAIN-SUFFIX,sycbbs.com,AD-BAN
  - DOMAIN-SUFFIX,synacast.com,AD-BAN
  - DOMAIN-SUFFIX,sysdig.com,AD-BAN
  - DOMAIN-SUFFIX,talkingdata.com,AD-BAN
  - DOMAIN-SUFFIX,talkingdata.net,AD-BAN
  - DOMAIN-SUFFIX,tansuotv.com,AD-BAN
  - DOMAIN-SUFFIX,tanv.com,AD-BAN
  - DOMAIN-SUFFIX,tanx.com,AD-BAN
  - DOMAIN-SUFFIX,tapjoy.cn,AD-BAN
  - DOMAIN-SUFFIX,th7.cn,AD-BAN
  - DOMAIN-SUFFIX,thoughtleadr.com,AD-BAN
  - DOMAIN-SUFFIX,tianmidian.com,AD-BAN
  - DOMAIN-SUFFIX,tiqcdn.com,AD-BAN
  - DOMAIN-SUFFIX,touclick.com,AD-BAN
  - DOMAIN-SUFFIX,trafficjam.cn,AD-BAN
  - DOMAIN-SUFFIX,trafficmp.com,AD-BAN
  - DOMAIN-SUFFIX,tuia.cn,AD-BAN
  - DOMAIN-SUFFIX,ueadlian.com,AD-BAN
  - DOMAIN-SUFFIX,uerzyr.cn,AD-BAN
  - DOMAIN-SUFFIX,ugdtimg.com,AD-BAN
  - DOMAIN-SUFFIX,ugvip.com,AD-BAN
  - DOMAIN-SUFFIX,ujian.cc,AD-BAN
  - DOMAIN-SUFFIX,ukeiae.com,AD-BAN
  - DOMAIN-SUFFIX,umeng.co,AD-BAN
  - DOMAIN-SUFFIX,umeng.com,AD-BAN
  - DOMAIN-SUFFIX,umtrack.com,AD-BAN
  - DOMAIN-SUFFIX,unimhk.com,AD-BAN
  - DOMAIN-SUFFIX,union-wifi.com,AD-BAN
  - DOMAIN-SUFFIX,union001.com,AD-BAN
  - DOMAIN-SUFFIX,unionsy.com,AD-BAN
  - DOMAIN-SUFFIX,unlitui.com,AD-BAN
  - DOMAIN-SUFFIX,uri6.com,AD-BAN
  - DOMAIN-SUFFIX,ushaqi.com,AD-BAN
  - DOMAIN-SUFFIX,usingde.com,AD-BAN
  - DOMAIN-SUFFIX,uuzu.com,AD-BAN
  - DOMAIN-SUFFIX,uyunad.com,AD-BAN
  - DOMAIN-SUFFIX,vamaker.com,AD-BAN
  - DOMAIN-SUFFIX,vlion.cn,AD-BAN
  - DOMAIN-SUFFIX,voiceads.cn,AD-BAN
  - DOMAIN-SUFFIX,voiceads.com,AD-BAN
  - DOMAIN-SUFFIX,vpon.com,AD-BAN
  - DOMAIN-SUFFIX,vungle.cn,AD-BAN
  - DOMAIN-SUFFIX,vungle.com,AD-BAN
  - DOMAIN-SUFFIX,waps.cn,AD-BAN
  - DOMAIN-SUFFIX,wapx.cn,AD-BAN
  - DOMAIN-SUFFIX,webterren.com,AD-BAN
  - DOMAIN-SUFFIX,whpxy.com,AD-BAN
  - DOMAIN-SUFFIX,winads.cn,AD-BAN
  - DOMAIN-SUFFIX,winasdaq.com,AD-BAN
  - DOMAIN-SUFFIX,wiyun.com,AD-BAN
  - DOMAIN-SUFFIX,wooboo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,wqmobile.com,AD-BAN
  - DOMAIN-SUFFIX,wrating.com,AD-BAN
  - DOMAIN-SUFFIX,wumii.cn,AD-BAN
  - DOMAIN-SUFFIX,wwads.cn,AD-BAN
  - DOMAIN-SUFFIX,xcy8.com,AD-BAN
  - DOMAIN-SUFFIX,xdrig.com,AD-BAN
  - DOMAIN-SUFFIX,xiaozhen.com,AD-BAN
  - DOMAIN-SUFFIX,xibao100.com,AD-BAN
  - DOMAIN-SUFFIX,xtgreat.com,AD-BAN
  - DOMAIN-SUFFIX,xy.com,AD-BAN
  - DOMAIN-SUFFIX,yandui.com,AD-BAN
  - DOMAIN-SUFFIX,yigao.com,AD-BAN
  - DOMAIN-SUFFIX,yijifen.com,AD-BAN
  - DOMAIN-SUFFIX,yinooo.com,AD-BAN
  - DOMAIN-SUFFIX,yiqifa.com,AD-BAN
  - DOMAIN-SUFFIX,yiwk.com,AD-BAN
  - DOMAIN-SUFFIX,ylunion.com,AD-BAN
  - DOMAIN-SUFFIX,ymapp.com,AD-BAN
  - DOMAIN-SUFFIX,ymcdn.cn,AD-BAN
  - DOMAIN-SUFFIX,yongyuelm.com,AD-BAN
  - DOMAIN-SUFFIX,yooli.com,AD-BAN
  - DOMAIN-SUFFIX,youmi.net,AD-BAN
  - DOMAIN-SUFFIX,youxiaoad.com,AD-BAN
  - DOMAIN-SUFFIX,yoyi.com.cn,AD-BAN
  - DOMAIN-SUFFIX,yoyi.tv,AD-BAN
  - DOMAIN-SUFFIX,yrxmr.com,AD-BAN
  - DOMAIN-SUFFIX,ysjwj.com,AD-BAN
  - DOMAIN-SUFFIX,yunjiasu.com,AD-BAN
  - DOMAIN-SUFFIX,yunpifu.cn,AD-BAN
  - DOMAIN-SUFFIX,zampdsp.com,AD-BAN
  - DOMAIN-SUFFIX,zamplus.com,AD-BAN
  - DOMAIN-SUFFIX,zcdsp.com,AD-BAN
  - DOMAIN-SUFFIX,zhidian3g.cn,AD-BAN
  - DOMAIN-SUFFIX,zhiziyun.com,AD-BAN
  - DOMAIN-SUFFIX,zhjfad.com,AD-BAN
  - DOMAIN-SUFFIX,zqzxz.com,AD-BAN
  - DOMAIN-SUFFIX,zzsx8.com,AD-BAN
  - DOMAIN-SUFFIX,acuityplatform.com,AD-BAN
  - DOMAIN-SUFFIX,ad-stir.com,AD-BAN
  - DOMAIN-SUFFIX,ad-survey.com,AD-BAN
  - DOMAIN-SUFFIX,ad4game.com,AD-BAN
  - DOMAIN-SUFFIX,adcloud.jp,AD-BAN
  - DOMAIN-SUFFIX,adcolony.com,AD-BAN
  - DOMAIN-SUFFIX,addthis.com,AD-BAN
  - DOMAIN-SUFFIX,adfurikun.jp,AD-BAN
  - DOMAIN-SUFFIX,adhigh.net,AD-BAN
  - DOMAIN-SUFFIX,adhood.com,AD-BAN
  - DOMAIN-SUFFIX,adinall.com,AD-BAN
  - DOMAIN-SUFFIX,adition.com,AD-BAN
  - DOMAIN-SUFFIX,adk2x.com,AD-BAN
  - DOMAIN-SUFFIX,admarket.mobi,AD-BAN
  - DOMAIN-SUFFIX,admarvel.com,AD-BAN
  - DOMAIN-SUFFIX,admedia.com,AD-BAN
  - DOMAIN-SUFFIX,adnxs.com,AD-BAN
  - DOMAIN-SUFFIX,adotmob.com,AD-BAN
  - DOMAIN-SUFFIX,adperium.com,AD-BAN
  - DOMAIN-SUFFIX,adriver.ru,AD-BAN
  - DOMAIN-SUFFIX,adroll.com,AD-BAN
  - DOMAIN-SUFFIX,adsco.re,AD-BAN
  - DOMAIN-SUFFIX,adservice.com,AD-BAN
  - DOMAIN-SUFFIX,adsrvr.org,AD-BAN
  - DOMAIN-SUFFIX,adsymptotic.com,AD-BAN
  - DOMAIN-SUFFIX,adtaily.com,AD-BAN
  - DOMAIN-SUFFIX,adtech.de,AD-BAN
  - DOMAIN-SUFFIX,adtechjp.com,AD-BAN
  - DOMAIN-SUFFIX,adtechus.com,AD-BAN
  - DOMAIN-SUFFIX,airpush.com,AD-BAN
  - DOMAIN-SUFFIX,am15.net,AD-BAN
  - DOMAIN-SUFFIX,amobee.com,AD-BAN
  - DOMAIN-SUFFIX,appier.net,AD-BAN
  - DOMAIN-SUFFIX,applift.com,AD-BAN
  - DOMAIN-SUFFIX,apsalar.com,AD-BAN
  - DOMAIN-SUFFIX,atas.io,AD-BAN
  - DOMAIN-SUFFIX,awempire.com,AD-BAN
  - DOMAIN-SUFFIX,axonix.com,AD-BAN
  - DOMAIN-SUFFIX,beintoo.com,AD-BAN
  - DOMAIN-SUFFIX,bepolite.eu,AD-BAN
  - DOMAIN-SUFFIX,bidtheatre.com,AD-BAN
  - DOMAIN-SUFFIX,bidvertiser.com,AD-BAN
  - DOMAIN-SUFFIX,blismedia.com,AD-BAN
  - DOMAIN-SUFFIX,brucelead.com,AD-BAN
  - DOMAIN-SUFFIX,bttrack.com,AD-BAN
  - DOMAIN-SUFFIX,casalemedia.com,AD-BAN
  - DOMAIN-SUFFIX,celtra.com,AD-BAN
  - DOMAIN-SUFFIX,channeladvisor.com,AD-BAN
  - DOMAIN-SUFFIX,connexity.net,AD-BAN
  - DOMAIN-SUFFIX,criteo.com,AD-BAN
  - DOMAIN-SUFFIX,criteo.net,AD-BAN
  - DOMAIN-SUFFIX,csbew.com,AD-BAN
  - DOMAIN-SUFFIX,directrev.com,AD-BAN
  - DOMAIN-SUFFIX,dumedia.ru,AD-BAN
  - DOMAIN-SUFFIX,effectivemeasure.com,AD-BAN
  - DOMAIN-SUFFIX,effectivemeasure.net,AD-BAN
  - DOMAIN-SUFFIX,eqads.com,AD-BAN
  - DOMAIN-SUFFIX,everesttech.net,AD-BAN
  - DOMAIN-SUFFIX,exoclick.com,AD-BAN
  - DOMAIN-SUFFIX,extend.tv,AD-BAN
  - DOMAIN-SUFFIX,eyereturn.com,AD-BAN
  - DOMAIN-SUFFIX,fastapi.net,AD-BAN
  - DOMAIN-SUFFIX,fastclick.com,AD-BAN
  - DOMAIN-SUFFIX,fastclick.net,AD-BAN
  - DOMAIN-SUFFIX,flurry.com,AD-BAN
  - DOMAIN-SUFFIX,gosquared.com,AD-BAN
  - DOMAIN-SUFFIX,gtags.net,AD-BAN
  - DOMAIN-SUFFIX,heyzap.com,AD-BAN
  - DOMAIN-SUFFIX,histats.com,AD-BAN
  - DOMAIN-SUFFIX,hitslink.com,AD-BAN
  - DOMAIN-SUFFIX,hot-mob.com,AD-BAN
  - DOMAIN-SUFFIX,hyperpromote.com,AD-BAN
  - DOMAIN-SUFFIX,i-mobile.co.jp,AD-BAN
  - DOMAIN-SUFFIX,imrworldwide.com,AD-BAN
  - DOMAIN-SUFFIX,inmobi.com,AD-BAN
  - DOMAIN-SUFFIX,inner-active.mobi,AD-BAN
  - DOMAIN-SUFFIX,intentiq.com,AD-BAN
  - DOMAIN-SUFFIX,inter1ads.com,AD-BAN
  - DOMAIN-SUFFIX,ipredictive.com,AD-BAN
  - DOMAIN-SUFFIX,ironsrc.com,AD-BAN
  - DOMAIN-SUFFIX,iskyworker.com,AD-BAN
  - DOMAIN-SUFFIX,jizzads.com,AD-BAN
  - DOMAIN-SUFFIX,juicyads.com,AD-BAN
  - DOMAIN-SUFFIX,kochava.com,AD-BAN
  - DOMAIN-SUFFIX,leadbolt.com,AD-BAN
  - DOMAIN-SUFFIX,leadbolt.net,AD-BAN
  - DOMAIN-SUFFIX,leadboltads.net,AD-BAN
  - DOMAIN-SUFFIX,leadboltapps.net,AD-BAN
  - DOMAIN-SUFFIX,leadboltmobile.net,AD-BAN
  - DOMAIN-SUFFIX,lenzmx.com,AD-BAN
  - DOMAIN-SUFFIX,liveadvert.com,AD-BAN
  - DOMAIN-SUFFIX,marketgid.com,AD-BAN
  - DOMAIN-SUFFIX,marketo.com,AD-BAN
  - DOMAIN-SUFFIX,mdotm.com,AD-BAN
  - DOMAIN-SUFFIX,medialytics.com,AD-BAN
  - DOMAIN-SUFFIX,medialytics.io,AD-BAN
  - DOMAIN-SUFFIX,meetrics.com,AD-BAN
  - DOMAIN-SUFFIX,meetrics.net,AD-BAN
  - DOMAIN-SUFFIX,mgid.com,AD-BAN
  - DOMAIN-SUFFIX,millennialmedia.com,AD-BAN
  - DOMAIN-SUFFIX,mobadme.jp,AD-BAN
  - DOMAIN-SUFFIX,mobfox.com,AD-BAN
  - DOMAIN-SUFFIX,mobileadtrading.com,AD-BAN
  - DOMAIN-SUFFIX,mobilityware.com,AD-BAN
  - DOMAIN-SUFFIX,mojiva.com,AD-BAN
  - DOMAIN-SUFFIX,mookie1.com,AD-BAN
  - DOMAIN-SUFFIX,msads.net,AD-BAN
  - DOMAIN-SUFFIX,mydas.mobi,AD-BAN
  - DOMAIN-SUFFIX,nend.net,AD-BAN
  - DOMAIN-SUFFIX,netshelter.net,AD-BAN
  - DOMAIN-SUFFIX,nexage.com,AD-BAN
  - DOMAIN-SUFFIX,owneriq.net,AD-BAN
  - DOMAIN-SUFFIX,pixels.asia,AD-BAN
  - DOMAIN-SUFFIX,plista.com,AD-BAN
  - DOMAIN-SUFFIX,popads.net,AD-BAN
  - DOMAIN-SUFFIX,powerlinks.com,AD-BAN
  - DOMAIN-SUFFIX,propellerads.com,AD-BAN
  - DOMAIN-SUFFIX,quantserve.com,AD-BAN
  - DOMAIN-SUFFIX,rayjump.com,AD-BAN
  - DOMAIN-SUFFIX,revdepo.com,AD-BAN
  - DOMAIN-SUFFIX,rubiconproject.com,AD-BAN
  - DOMAIN-SUFFIX,sape.ru,AD-BAN
  - DOMAIN-SUFFIX,scorecardresearch.com,AD-BAN
  - DOMAIN-SUFFIX,segment.com,AD-BAN
  - DOMAIN-SUFFIX,serving-sys.com,AD-BAN
  - DOMAIN-SUFFIX,sharethis.com,AD-BAN
  - DOMAIN-SUFFIX,smaato.com,AD-BAN
  - DOMAIN-SUFFIX,smaato.net,AD-BAN
  - DOMAIN-SUFFIX,smartadserver.com,AD-BAN
  - DOMAIN-SUFFIX,smartnews-ads.com,AD-BAN
  - DOMAIN-SUFFIX,startapp.com,AD-BAN
  - DOMAIN-SUFFIX,startappexchange.com,AD-BAN
  - DOMAIN-SUFFIX,statcounter.com,AD-BAN
  - DOMAIN-SUFFIX,steelhousemedia.com,AD-BAN
  - DOMAIN-SUFFIX,stickyadstv.com,AD-BAN
  - DOMAIN-SUFFIX,supersonic.com,AD-BAN
  - DOMAIN-SUFFIX,taboola.com,AD-BAN
  - DOMAIN-SUFFIX,tapjoy.com,AD-BAN
  - DOMAIN-SUFFIX,tapjoyads.com,AD-BAN
  - DOMAIN-SUFFIX,trafficjunky.com,AD-BAN
  - DOMAIN-SUFFIX,trafficjunky.net,AD-BAN
  - DOMAIN-SUFFIX,tribalfusion.com,AD-BAN
  - DOMAIN-SUFFIX,turn.com,AD-BAN
  - DOMAIN-SUFFIX,uberads.com,AD-BAN
  - DOMAIN-SUFFIX,vidoomy.com,AD-BAN
  - DOMAIN-SUFFIX,viglink.com,AD-BAN
  - DOMAIN-SUFFIX,voicefive.com,AD-BAN
  - DOMAIN-SUFFIX,wedolook.com,AD-BAN
  - DOMAIN-SUFFIX,yadro.ru,AD-BAN
  - DOMAIN-SUFFIX,yengo.com,AD-BAN
  - DOMAIN-SUFFIX,zedo.com,AD-BAN
  - DOMAIN-SUFFIX,zemanta.com,AD-BAN
  - DOMAIN-SUFFIX,11h5.com,AD-BAN
  - DOMAIN-SUFFIX,1kxun.mobi,AD-BAN
  - DOMAIN-SUFFIX,26zsd.cn,AD-BAN
  - DOMAIN-SUFFIX,519397.com,AD-BAN
  - DOMAIN-SUFFIX,626uc.com,AD-BAN
  - DOMAIN-SUFFIX,915.com,AD-BAN
  - DOMAIN-SUFFIX,appget.cn,AD-BAN
  - DOMAIN-SUFFIX,appuu.cn,AD-BAN
  - DOMAIN-SUFFIX,coinhive.com,AD-BAN
  - DOMAIN-SUFFIX,huodonghezi.cn,AD-BAN
  - DOMAIN-SUFFIX,vcbn65.xyz,AD-BAN
  - DOMAIN-SUFFIX,wanfeng1.com,AD-BAN
  - DOMAIN-SUFFIX,wep016.top,AD-BAN
  - DOMAIN-SUFFIX,win-stock.com.cn,AD-BAN
  - DOMAIN-SUFFIX,zantainet.com,AD-BAN
  - DOMAIN-SUFFIX,dh54wf.xyz,AD-BAN
  - DOMAIN-SUFFIX,g2q3e.cn,AD-BAN
  - DOMAIN-SUFFIX,114so.cn,AD-BAN
  - DOMAIN-SUFFIX,go.10086.cn,AD-BAN
  - DOMAIN-SUFFIX,hivedata.cc,AD-BAN
  - DOMAIN-SUFFIX,navi.gd.chinamobile.com,AD-BAN
  - DOMAIN-SUFFIX,a.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,adgeo.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.126.net,AD-BAN
  - DOMAIN-SUFFIX,bobo.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,c.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,clkservice.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,conv.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,dsp-impr2.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,dsp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,fa.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,g.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,g1.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,gb.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,gorgon.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,haitaoad.nosdn.127.net,AD-BAN
  - DOMAIN-SUFFIX,iadmatvideo.nosdn.127.net,AD-BAN
  - DOMAIN-SUFFIX,img1.126.net,AD-BAN
  - DOMAIN-SUFFIX,img2.126.net,AD-BAN
  - DOMAIN-SUFFIX,ir.mail.126.com,AD-BAN
  - DOMAIN-SUFFIX,ir.mail.yeah.net,AD-BAN
  - DOMAIN-SUFFIX,mimg.126.net,AD-BAN
  - DOMAIN-SUFFIX,nc004x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,nc045x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,nex.corp.163.com,AD-BAN
  - DOMAIN-SUFFIX,oimagea2.ydstatic.com,AD-BAN
  - DOMAIN-SUFFIX,pagechoice.net,AD-BAN
  - DOMAIN-SUFFIX,prom.gome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,qchannel0d.cn,AD-BAN
  - DOMAIN-SUFFIX,qt002x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,rlogs.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,static.flv.uuzuonline.com,AD-BAN
  - DOMAIN-SUFFIX,tb060x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,tb104x.corp.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,union.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,wanproxy.127.net,AD-BAN
  - DOMAIN-SUFFIX,ydpushserver.youdao.com,AD-BAN
  - DOMAIN-SUFFIX,cvda.17173.com,AD-BAN
  - DOMAIN-SUFFIX,imgapp.yeyou.com,AD-BAN
  - DOMAIN-SUFFIX,log1.17173.com,AD-BAN
  - DOMAIN-SUFFIX,s.17173cdn.com,AD-BAN
  - DOMAIN-SUFFIX,ue.yeyoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,vda.17173.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.wanmei.com,AD-BAN
  - DOMAIN-SUFFIX,gg.stargame.com,AD-BAN
  - DOMAIN-SUFFIX,dl.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,download.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,houtai.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,jifen.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,jifendownload.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,minipage.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,wan.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,zhushou.2345.cn,AD-BAN
  - DOMAIN-SUFFIX,3600.com,AD-BAN
  - DOMAIN-SUFFIX,gamebox.360.cn,AD-BAN
  - DOMAIN-SUFFIX,jiagu.360.cn,AD-BAN
  - DOMAIN-SUFFIX,kuaikan.netmon.360safe.com,AD-BAN
  - DOMAIN-SUFFIX,leak.360.cn,AD-BAN
  - DOMAIN-SUFFIX,lianmeng.360.cn,AD-BAN
  - DOMAIN-SUFFIX,pub.se.360.cn,AD-BAN
  - DOMAIN-SUFFIX,s.so.360.cn,AD-BAN
  - DOMAIN-SUFFIX,shouji.360.cn,AD-BAN
  - DOMAIN-SUFFIX,soft.data.weather.360.cn,AD-BAN
  - DOMAIN-SUFFIX,stat.360safe.com,AD-BAN
  - DOMAIN-SUFFIX,stat.m.360.cn,AD-BAN
  - DOMAIN-SUFFIX,update.360safe.com,AD-BAN
  - DOMAIN-SUFFIX,wan.360.cn,AD-BAN
  - DOMAIN-SUFFIX,58.xgo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,brandshow.58.com,AD-BAN
  - DOMAIN-SUFFIX,imp.xgo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,jing.58.com,AD-BAN
  - DOMAIN-SUFFIX,stat.xgo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,track.58.com,AD-BAN
  - DOMAIN-SUFFIX,tracklog.58.com,AD-BAN
  - DOMAIN-SUFFIX,acjs.aliyun.com,AD-BAN
  - DOMAIN-SUFFIX,adash-c.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,adash-c.ut.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,adashx4yt.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,adashxgc.ut.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,afp.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,ai.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,alipaylog.com,AD-BAN
  - DOMAIN-SUFFIX,atanx.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,atanx2.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,fav.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,g.click.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,g.tbcdn.cn,AD-BAN
  - DOMAIN-SUFFIX,gma.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,gtmsdd.alicdn.com,AD-BAN
  - DOMAIN-SUFFIX,hydra.alibaba.com,AD-BAN
  - DOMAIN-SUFFIX,m.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,pindao.huoban.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,re.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,redirect.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,rj.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,sdkinit.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,show.re.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,simaba.m.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,simaba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,srd.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,strip.taobaocdn.com,AD-BAN
  - DOMAIN-SUFFIX,tns.simba.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,tyh.taobao.com,AD-BAN
  - DOMAIN-SUFFIX,userimg.qunar.com,AD-BAN
  - DOMAIN-SUFFIX,yiliao.hupan.com,AD-BAN
  - DOMAIN-SUFFIX,3dns-2.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,3dns-3.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,activate-sea.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,activate-sjc0.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,activate.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,adobe-dns-2.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,adobe-dns-3.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,adobe-dns.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,ereg.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,geo2.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,hl2rcv.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,hlrcv.stage.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,lm.licenses.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,lmlicenses.wip4.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,na1r.services.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,na2m-pr.licenses.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,practivate.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,wip3.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,wwis-dubc1-vip60.adobe.com,AD-BAN
  - DOMAIN-SUFFIX,adserver.unityads.unity3d.com,AD-BAN
  - DOMAIN-SUFFIX,33.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,adproxy.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,al.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,alert.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,applogapi.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,c.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,cmx.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,dspmnt.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,pcd.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,push.app.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,pvx.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,rd.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,rdx.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,stats.autohome.com.cn,AD-BAN
  - DOMAIN-SUFFIX,a.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,a.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ad.duapps.com,AD-BAN
  - DOMAIN-SUFFIX,ad.player.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,adm.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,adm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,adscdn.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,adscdn.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,adx.xiaodutv.com,AD-BAN
  - DOMAIN-SUFFIX,ae.bdstatic.com,AD-BAN
  - DOMAIN-SUFFIX,afd.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,afd.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,als.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,als.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,anquan.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,anquan.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,antivirus.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,api.mobula.sdk.duapps.com,AD-BAN
  - DOMAIN-SUFFIX,appc.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,appc.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,as.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,as.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,baichuan.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,baidu9635.com,AD-BAN
  - DOMAIN-SUFFIX,baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,baidutv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,banlv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,bar.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,bdplus.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,btlaunch.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,c.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,c.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cb.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cb.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cbjs.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cbjs.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cbjslog.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cbjslog.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cjhq.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cjhq.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cleaner.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,click.bes.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,click.hm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,click.qianqian.com,AD-BAN
  - DOMAIN-SUFFIX,cm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpro.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cpro.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpro.baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,cpro.tieba.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpro.zhidao.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpro2.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,cpro2.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,cpu-admin.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,crs.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,crs.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,datax.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl-vip.bav.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl-vip.pcfaster.baidu.co.th,AD-BAN
  - DOMAIN-SUFFIX,dl.client.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl.ops.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl1sw.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dl2.bav.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dlsw.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dlsw.br.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,download.bav.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,download.sd.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,drmcmm.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,drmcmm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dup.baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,dxp.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,dzl.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,e.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,e.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,eclick.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,eclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ecma.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,ecmb.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,ecmc.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,eiv.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,eiv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,em.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ers.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,f10.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,fc-.cdn.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,fc-feed.cdn.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,fclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,fexclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,g.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,gimg.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,guanjia.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,hc.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,hc.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,hm.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,hm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,hmma.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,hmma.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,hpd.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,hpd.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,idm-su.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,iebar.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ikcode.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,imageplus.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,imageplus.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,img.taotaosou.cn,AD-BAN
  - DOMAIN-SUFFIX,img01.taotaosou.cn,AD-BAN
  - DOMAIN-SUFFIX,itsdata.map.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,j.br.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,kstj.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,log.music.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,log.nuomi.com,AD-BAN
  - DOMAIN-SUFFIX,m1.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ma.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,ma.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,mg09.zhaopin.com,AD-BAN
  - DOMAIN-SUFFIX,mipcache.bdstatic.com,AD-BAN
  - DOMAIN-SUFFIX,mobads-logs.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,mobads-logs.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,mobads.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,mobads.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,mpro.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,mtj.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,mtj.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,neirong.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,nsclick.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,nsclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,nsclickvideo.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,openrcv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,pc.videoclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,pos.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,pups.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,pups.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,pups.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,push.music.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,push.zhanzhang.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,qchannel0d.cn,AD-BAN
  - DOMAIN-SUFFIX,qianclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,release.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,res.limei.com,AD-BAN
  - DOMAIN-SUFFIX,res.mi.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,rigel.baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,river.zhidao.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,rj.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,rj.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,rp.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,rp.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,rplog.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,s.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,sclick.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,sestat.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,shadu.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,share.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,sobar.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,sobartop.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,spcode.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,spcode.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,stat.v.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,su.bdimg.com,AD-BAN
  - DOMAIN-SUFFIX,su.bdstatic.com,AD-BAN
  - DOMAIN-SUFFIX,tk.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,tk.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tkweb.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tob-cms.bj.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,toolbar.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tracker.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tuijian.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,tuisong.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,tuisong.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ubmcmm.baidustatic.com,AD-BAN
  - DOMAIN-SUFFIX,ucstat.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,ucstat.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ulic.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,ulog.imap.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,union.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,union.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,unionimage.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,utility.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,utility.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,utk.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,utk.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,videopush.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,videopush.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,vv84.bj.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,w.gdown.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,w.x.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,wangmeng.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,wangmeng.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,weishi.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,wenku-cms.bj.bcebos.com,AD-BAN
  - DOMAIN-SUFFIX,wisepush.video.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,wm.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,wm.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,znsv.baidu.cn,AD-BAN
  - DOMAIN-SUFFIX,znsv.baidu.com,AD-BAN
  - DOMAIN-SUFFIX,zz.bdstatic.com,AD-BAN
  - DOMAIN-SUFFIX,zzy1.quyaoya.com,AD-BAN
  - DOMAIN-SUFFIX,ad.zhangyue.com,AD-BAN
  - DOMAIN-SUFFIX,adm.ps.easou.com,AD-BAN
  - DOMAIN-SUFFIX,aishowbger.com,AD-BAN
  - DOMAIN-SUFFIX,api.itaoxiaoshuo.com,AD-BAN
  - DOMAIN-SUFFIX,assets.ps.easou.com,AD-BAN
  - DOMAIN-SUFFIX,bbcoe.cn,AD-BAN
  - DOMAIN-SUFFIX,cj.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,dkeyn.com,AD-BAN
  - DOMAIN-SUFFIX,drdwy.com,AD-BAN
  - DOMAIN-SUFFIX,e.aa985.cn,AD-BAN
  - DOMAIN-SUFFIX,e.v02u9.cn,AD-BAN
  - DOMAIN-SUFFIX,e701.net,AD-BAN
  - DOMAIN-SUFFIX,ehxyz.com,AD-BAN
  - DOMAIN-SUFFIX,ethod.gzgmjcx.com,AD-BAN
  - DOMAIN-SUFFIX,focuscat.com,AD-BAN
  - DOMAIN-SUFFIX,game.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,hdswgc.com,AD-BAN
  - DOMAIN-SUFFIX,jyd.fjzdmy.com,AD-BAN
  - DOMAIN-SUFFIX,m.ourlj.com,AD-BAN
  - DOMAIN-SUFFIX,m.txtxr.com,AD-BAN
  - DOMAIN-SUFFIX,m.vsxet.com,AD-BAN
  - DOMAIN-SUFFIX,miam4.cn,AD-BAN
  - DOMAIN-SUFFIX,o.if.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,p.vq6nsu.cn,AD-BAN
  - DOMAIN-SUFFIX,picture.duokan.com,AD-BAN
  - DOMAIN-SUFFIX,push.zhangyue.com,AD-BAN
  - DOMAIN-SUFFIX,pyerc.com,AD-BAN
  - DOMAIN-SUFFIX,s1.cmfu.com,AD-BAN
  - DOMAIN-SUFFIX,sc.shayugg.com,AD-BAN
  - DOMAIN-SUFFIX,sdk.cferw.com,AD-BAN
  - DOMAIN-SUFFIX,sezvc.com,AD-BAN
  - DOMAIN-SUFFIX,sys.zhangyue.com,AD-BAN
  - DOMAIN-SUFFIX,tjlog.ps.easou.com,AD-BAN
  - DOMAIN-SUFFIX,tongji.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,ut2.shuqistat.com,AD-BAN
  - DOMAIN-SUFFIX,xgcsr.com,AD-BAN
  - DOMAIN-SUFFIX,xjq.jxmqkj.com,AD-BAN
  - DOMAIN-SUFFIX,xpe.cxaerp.com,AD-BAN
  - DOMAIN-SUFFIX,xtzxmy.com,AD-BAN
  - DOMAIN-SUFFIX,xyrkl.com,AD-BAN
  - DOMAIN-SUFFIX,zhuanfakong.com,AD-BAN
  - DOMAIN-SUFFIX,ad.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,dsp.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,ic.snssdk.com,AD-BAN
  - DOMAIN-SUFFIX,log.snssdk.com,AD-BAN
  - DOMAIN-SUFFIX,nativeapp.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,pangolin-sdk-toutiao-b.com,AD-BAN
  - DOMAIN-SUFFIX,pangolin-sdk-toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,pangolin.snssdk.com,AD-BAN
  - DOMAIN-SUFFIX,partner.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,pglstatp-toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,sm.toutiao.com,AD-BAN
  - DOMAIN-SUFFIX,a.dangdang.com,AD-BAN
  - DOMAIN-SUFFIX,click.dangdang.com,AD-BAN
  - DOMAIN-SUFFIX,schprompt.dangdang.com,AD-BAN
  - DOMAIN-SUFFIX,t.dangdang.com,AD-BAN
  - DOMAIN-SUFFIX,ad.duomi.com,AD-BAN
  - DOMAIN-SUFFIX,boxshows.com,AD-BAN
  - DOMAIN-SUFFIX,staticxx.facebook.com,AD-BAN
  - DOMAIN-SUFFIX,click1n.soufun.com,AD-BAN
  - DOMAIN-SUFFIX,clickm.fang.com,AD-BAN
  - DOMAIN-SUFFIX,clickn.fang.com,AD-BAN
  - DOMAIN-SUFFIX,countpvn.light.fang.com,AD-BAN
  - DOMAIN-SUFFIX,countubn.light.soufun.com,AD-BAN
  - DOMAIN-SUFFIX,mshow.fang.com,AD-BAN
  - DOMAIN-SUFFIX,tongji.home.soufun.com,AD-BAN
  - DOMAIN-SUFFIX,admob.com,AD-BAN
  - DOMAIN-SUFFIX,ads.gmodules.com,AD-BAN
  - DOMAIN-SUFFIX,ads.google.com,AD-BAN
  - DOMAIN-SUFFIX,adservice.google.com,AD-BAN
  - DOMAIN-SUFFIX,afd.l.google.com,AD-BAN
  - DOMAIN-SUFFIX,badad.googleplex.com,AD-BAN
  - DOMAIN-SUFFIX,csi.gstatic.com,AD-BAN
  - DOMAIN-SUFFIX,doubleclick.com,AD-BAN
  - DOMAIN-SUFFIX,doubleclick.net,AD-BAN
  - DOMAIN-SUFFIX,google-analytics.com,AD-BAN
  - DOMAIN-SUFFIX,googleadservices.com,AD-BAN
  - DOMAIN-SUFFIX,googleadsserving.cn,AD-BAN
  - DOMAIN-SUFFIX,googlecommerce.com,AD-BAN
  - DOMAIN-SUFFIX,googlesyndication.com,AD-BAN
  - DOMAIN-SUFFIX,mobileads.google.com,AD-BAN
  - DOMAIN-SUFFIX,pagead-tpc.l.google.com,AD-BAN
  - DOMAIN-SUFFIX,pagead.google.com,AD-BAN
  - DOMAIN-SUFFIX,pagead.l.google.com,AD-BAN
  - DOMAIN-SUFFIX,service.urchin.com,AD-BAN
  - DOMAIN-SUFFIX,ads.union.jd.com,AD-BAN
  - DOMAIN-SUFFIX,c-nfa.jd.com,AD-BAN
  - DOMAIN-SUFFIX,cps.360buy.com,AD-BAN
  - DOMAIN-SUFFIX,img-x.jd.com,AD-BAN
  - DOMAIN-SUFFIX,jrclick.jd.com,AD-BAN
  - DOMAIN-SUFFIX,jzt.jd.com,AD-BAN
  - DOMAIN-SUFFIX,policy.jd.com,AD-BAN
  - DOMAIN-SUFFIX,stat.m.jd.com,AD-BAN
  - DOMAIN-SUFFIX,ads.service.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,adsfile.bssdlbig.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,d.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,downmobile.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,gad.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,game.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,gamebox.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,gcapi.sy.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,gg.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,install.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,install2.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,kgmobilestat.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,kuaikaiapp.com,AD-BAN
  - DOMAIN-SUFFIX,log.stat.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,log.web.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,minidcsc.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,mo.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,mobilelog.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,msg.mobile.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,mvads.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,p.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,push.mobile.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,rtmonitor.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,sdn.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,tj.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,update.mobile.kugou.com,AD-BAN
  - DOMAIN-SUFFIX,apk.shouji.koowo.com,AD-BAN
  - DOMAIN-SUFFIX,deliver.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,g.koowo.com,AD-BAN
  - DOMAIN-SUFFIX,g.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,kwmsg.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,log.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,mobilead.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,msclick2.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,msphoneclick.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,updatepage.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,wa.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,webstat.kuwo.cn,AD-BAN
  - DOMAIN-SUFFIX,aider-res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,api-flow.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,api-game.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,api-push.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,aries.mzres.com,AD-BAN
  - DOMAIN-SUFFIX,bro.flyme.cn,AD-BAN
  - DOMAIN-SUFFIX,cal.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,ebook.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,ebook.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,game-res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,game.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,infocenter.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,openapi-news.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,push.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,reader.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,reader.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,t-e.flyme.cn,AD-BAN
  - DOMAIN-SUFFIX,t-flow.flyme.cn,AD-BAN
  - DOMAIN-SUFFIX,tongji-res1.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,tongji.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,umid.orion.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,upush.res.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,uxip.meizu.com,AD-BAN
  - DOMAIN-SUFFIX,a.koudai.com,AD-BAN
  - DOMAIN-SUFFIX,adui.tg.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,corp.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,dc.meitustat.com,AD-BAN
  - DOMAIN-SUFFIX,gg.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,mdc.meitustat.com,AD-BAN
  - DOMAIN-SUFFIX,meitubeauty.meitudata.com,AD-BAN
  - DOMAIN-SUFFIX,message.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,rabbit.meitustat.com,AD-BAN
  - DOMAIN-SUFFIX,rabbit.tg.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,tuiguang.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,xiuxiu.android.dl.meitu.com,AD-BAN
  - DOMAIN-SUFFIX,xiuxiu.mobile.meitudata.com,AD-BAN
  - DOMAIN-SUFFIX,a.market.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,ad.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,ad1.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,adv.sec.intl.miui.com,AD-BAN
  - DOMAIN-SUFFIX,adv.sec.miui.com,AD-BAN
  - DOMAIN-SUFFIX,bss.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,d.g.mi.com,AD-BAN
  - DOMAIN-SUFFIX,data.mistat.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,de.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,dvb.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,jellyfish.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,migc.g.mi.com,AD-BAN
  - DOMAIN-SUFFIX,migcreport.g.mi.com,AD-BAN
  - DOMAIN-SUFFIX,notice.game.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,ppurifier.game.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,r.browser.miui.com,AD-BAN
  - DOMAIN-SUFFIX,security.browser.miui.com,AD-BAN
  - DOMAIN-SUFFIX,shenghuo.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,stat.pandora.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,union.mi.com,AD-BAN
  - DOMAIN-SUFFIX,wtradv.market.xiaomi.com,AD-BAN
  - DOMAIN-SUFFIX,ad.api.moji.com,AD-BAN
  - DOMAIN-SUFFIX,app.moji001.com,AD-BAN
  - DOMAIN-SUFFIX,cdn.moji002.com,AD-BAN
  - DOMAIN-SUFFIX,cdn2.moji002.com,AD-BAN
  - DOMAIN-SUFFIX,fds.api.moji.com,AD-BAN
  - DOMAIN-SUFFIX,log.moji.com,AD-BAN
  - DOMAIN-SUFFIX,stat.moji.com,AD-BAN
  - DOMAIN-SUFFIX,ugc.moji001.com,AD-BAN
  - DOMAIN-SUFFIX,ad.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,admgr.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,dload.qd.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,logger.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,s.qd.qingting.fm,AD-BAN
  - DOMAIN-SUFFIX,s.qd.qingtingfm.com,AD-BAN
  - DOMAIN-KEYWORD,omgmtaw,AD-BAN
  - DOMAIN,adsmind.apdcdn.tc.qq.com,AD-BAN
  - DOMAIN,adsmind.gdtimg.com,AD-BAN
  - DOMAIN,adsmind.tc.qq.com,AD-BAN
  - DOMAIN,pgdt.gtimg.cn,AD-BAN
  - DOMAIN,pgdt.gtimg.com,AD-BAN
  - DOMAIN,pgdt.ugdtimg.com,AD-BAN
  - DOMAIN,splashqqlive.gtimg.com,AD-BAN
  - DOMAIN,wa.gtimg.com,AD-BAN
  - DOMAIN,wxsnsdy.wxs.qq.com,AD-BAN
  - DOMAIN,wxsnsdythumb.wxs.qq.com,AD-BAN
  - DOMAIN-SUFFIX,act.qq.com,AD-BAN
  - DOMAIN-SUFFIX,ad.qun.qq.com,AD-BAN
  - DOMAIN-SUFFIX,adsfile.qq.com,AD-BAN
  - DOMAIN-SUFFIX,bugly.qq.com,AD-BAN
  - DOMAIN-SUFFIX,buluo.qq.com,AD-BAN
  - DOMAIN-SUFFIX,e.qq.com,AD-BAN
  - DOMAIN-SUFFIX,gdt.qq.com,AD-BAN
  - DOMAIN-SUFFIX,l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,monitor.qq.com,AD-BAN
  - DOMAIN-SUFFIX,pingma.qq.com,AD-BAN
  - DOMAIN-SUFFIX,pingtcss.qq.com,AD-BAN
  - DOMAIN-SUFFIX,report.qq.com,AD-BAN
  - DOMAIN-SUFFIX,tajs.qq.com,AD-BAN
  - DOMAIN-SUFFIX,tcss.qq.com,AD-BAN
  - DOMAIN-SUFFIX,uu.qq.com,AD-BAN
  - DOMAIN-SUFFIX,ebp.renren.com,AD-BAN
  - DOMAIN-SUFFIX,jebe.renren.com,AD-BAN
  - DOMAIN-SUFFIX,jebe.xnimg.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,adbox.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,add.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,adimg.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,adm.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,alitui.weibo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,biz.weibo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,cre.dp.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,dcads.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,dd.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,dmp.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,game.weibo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,gw5.push.mcp.weibo.cn,AD-BAN
  - DOMAIN-SUFFIX,leju.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,log.mix.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,mobileads.dx.cn,AD-BAN
  - DOMAIN-SUFFIX,newspush.sinajs.cn,AD-BAN
  - DOMAIN-SUFFIX,pay.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,sax.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,sax.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,saxd.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,sdkapp.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,sdkapp.uve.weibo.com,AD-BAN
  - DOMAIN-SUFFIX,sdkclick.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,slog.sina.com.cn,AD-BAN
  - DOMAIN-SUFFIX,trends.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,tui.weibo.com,AD-BAN
  - DOMAIN-SUFFIX,u1.img.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,wax.weibo.com.cn,AD-BAN
  - DOMAIN-SUFFIX,wbapp.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,wbapp.uve.weibo.com,AD-BAN
  - DOMAIN-SUFFIX,wbclick.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,wbpctips.mobile.sina.cn,AD-BAN
  - DOMAIN-SUFFIX,zymo.mps.weibo.com,AD-BAN
  - DOMAIN-SUFFIX,123.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,123.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,adsence.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,amfi.gou.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,brand.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,cpc.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,epro.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,fair.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,files2.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,galaxy.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,golden1.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,goto.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,inte.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,iwan.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,lu.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,lu.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,pb.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,pd.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,pv.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,theta.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,wan.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,wangmeng.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,applovin.com,AD-BAN
  - DOMAIN-SUFFIX,guangzhuiyuan.com,AD-BAN
  - DOMAIN-SUFFIX,ads-twitter.com,AD-BAN
  - DOMAIN-SUFFIX,ads.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,p.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,scribe.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,syndication-o.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,syndication.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,tellapart.com,AD-BAN
  - DOMAIN-SUFFIX,urls.api.twitter.com,AD-BAN
  - DOMAIN-SUFFIX,adslot.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,api.mp.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,applog.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,client.video.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,cms.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,dispatcher.upmc.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,huichuan.sm.cn,AD-BAN
  - DOMAIN-SUFFIX,log.cs.pp.cn,AD-BAN
  - DOMAIN-SUFFIX,m.uczzd.cn,AD-BAN
  - DOMAIN-SUFFIX,patriot.cs.pp.cn,AD-BAN
  - DOMAIN-SUFFIX,puds.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,server.m.pp.cn,AD-BAN
  - DOMAIN-SUFFIX,track.uc.cn,AD-BAN
  - DOMAIN-SUFFIX,u.uc123.com,AD-BAN
  - DOMAIN-SUFFIX,u.ucfly.com,AD-BAN
  - DOMAIN-SUFFIX,uc.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,ucsec.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,ucsec1.ucweb.com,AD-BAN
  - DOMAIN-SUFFIX,aoodoo.feng.com,AD-BAN
  - DOMAIN-SUFFIX,fengbuy.com,AD-BAN
  - DOMAIN-SUFFIX,push.feng.com,AD-BAN
  - DOMAIN-SUFFIX,we.tm,AD-BAN
  - DOMAIN-SUFFIX,yes1.feng.com,AD-BAN
  - DOMAIN-SUFFIX,ad.docer.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,adm.zookingsoft.com,AD-BAN
  - DOMAIN-SUFFIX,bannera.kingsoft-office-service.com,AD-BAN
  - DOMAIN-SUFFIX,bole.shangshufang.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,counter.kingsoft.com,AD-BAN
  - DOMAIN-SUFFIX,docerad.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,gou.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,hoplink.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,ic.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,img.gou.wpscdn.cn,AD-BAN
  - DOMAIN-SUFFIX,info.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,ios-informationplatform.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,minfo.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,mo.res.wpscdn.cn,AD-BAN
  - DOMAIN-SUFFIX,news.docer.com,AD-BAN
  - DOMAIN-SUFFIX,notify.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,pc.uf.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,pcfg.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,pixiu.shangshufang.ksosoft.com,AD-BAN
  - DOMAIN-SUFFIX,push.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,rating6.kingsoft-office-service.com,AD-BAN
  - DOMAIN-SUFFIX,up.wps.kingsoft.com,AD-BAN
  - DOMAIN-SUFFIX,wpsweb-dc.wps.cn,AD-BAN
  - DOMAIN-SUFFIX,c.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,cdsget.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,news-imgpb.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,wifiapidd.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,wkanc.51y5.net,AD-BAN
  - DOMAIN-SUFFIX,adse.ximalaya.com,AD-BAN
  - DOMAIN-SUFFIX,linkeye.ximalaya.com,AD-BAN
  - DOMAIN-SUFFIX,location.ximalaya.com,AD-BAN
  - DOMAIN-SUFFIX,xdcs-collector.ximalaya.com,AD-BAN
  - DOMAIN-SUFFIX,biz5.kankan.com,AD-BAN
  - DOMAIN-SUFFIX,float.kankan.com,AD-BAN
  - DOMAIN-SUFFIX,hub5btmain.sandai.net,AD-BAN
  - DOMAIN-SUFFIX,hub5emu.sandai.net,AD-BAN
  - DOMAIN-SUFFIX,logic.cpm.cm.kankan.com,AD-BAN
  - DOMAIN-SUFFIX,upgrade.xl9.xunlei.com,AD-BAN
  - DOMAIN-SUFFIX,ad.wretch.cc,AD-BAN
  - DOMAIN-SUFFIX,ads.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,adserver.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,adss.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.query.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,ane.yahoo.co.jp,AD-BAN
  - DOMAIN-SUFFIX,ard.yahoo.co.jp,AD-BAN
  - DOMAIN-SUFFIX,beap-bc.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,clicks.beap.bc.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,comet.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,doubleplay-conf-yql.media.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,flurry.com,AD-BAN
  - DOMAIN-SUFFIX,gemini.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,geo.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,js-apac-ss.ysm.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,locdrop.query.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,onepush.query.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,p3p.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,partnerads.ysm.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,ws.progrss.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,yads.yahoo.co.jp,AD-BAN
  - DOMAIN-SUFFIX,ybp.yahoo.com,AD-BAN
  - DOMAIN-SUFFIX,shrek.6.cn,AD-BAN
  - DOMAIN-SUFFIX,simba.6.cn,AD-BAN
  - DOMAIN-SUFFIX,union.6.cn,AD-BAN
  - DOMAIN-SUFFIX,logger.baofeng.com,AD-BAN
  - DOMAIN-SUFFIX,xs.houyi.baofeng.net,AD-BAN
  - DOMAIN-SUFFIX,dotcounter.douyutv.com,AD-BAN
  - DOMAIN-SUFFIX,api.newad.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,exp.3g.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,game.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,iis3g.deliver.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,mfp.deliver.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,stadig.ifeng.com,AD-BAN
  - DOMAIN-SUFFIX,adm.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,jobsfe.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,po.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,pub.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,pv.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,stat.funshion.com,AD-BAN
  - DOMAIN-SUFFIX,ad.m.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,afp.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,c.uaa.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,cloudpush.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,cm.passport.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,cupid.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,emoticon.sns.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,gamecenter.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,ifacelog.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,mbdlog.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,meta.video.qiyi.com,AD-BAN
  - DOMAIN-SUFFIX,msg.71.am,AD-BAN
  - DOMAIN-SUFFIX,msg1.video.qiyi.com,AD-BAN
  - DOMAIN-SUFFIX,msg2.video.qiyi.com,AD-BAN
  - DOMAIN-SUFFIX,paopao.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,paopaod.qiyipic.com,AD-BAN
  - DOMAIN-SUFFIX,policy.video.iqiyi.com,AD-BAN
  - DOMAIN-SUFFIX,yuedu.iqiyi.com,AD-BAN
  - IP-CIDR,101.227.200.0/24,AD-BAN,no-resolve
  - IP-CIDR,101.227.200.11/32,AD-BAN,no-resolve
  - IP-CIDR,101.227.200.28/32,AD-BAN,no-resolve
  - IP-CIDR,101.227.97.240/32,AD-BAN,no-resolve
  - IP-CIDR,124.192.153.42/32,AD-BAN,no-resolve
  - DOMAIN-SUFFIX,gug.ku6cdn.com,AD-BAN
  - DOMAIN-SUFFIX,pq.stat.ku6.com,AD-BAN
  - DOMAIN-SUFFIX,st.vq.ku6.cn,AD-BAN
  - DOMAIN-SUFFIX,static.ku6.com,AD-BAN
  - DOMAIN-SUFFIX,1.letvlive.com,AD-BAN
  - DOMAIN-SUFFIX,2.letvlive.com,AD-BAN
  - DOMAIN-SUFFIX,ark.letv.com,AD-BAN
  - DOMAIN-SUFFIX,dc.letv.com,AD-BAN
  - DOMAIN-SUFFIX,fz.letv.com,AD-BAN
  - DOMAIN-SUFFIX,g3.letv.com,AD-BAN
  - DOMAIN-SUFFIX,game.letvstore.com,AD-BAN
  - DOMAIN-SUFFIX,i0.letvimg.com,AD-BAN
  - DOMAIN-SUFFIX,i3.letvimg.com,AD-BAN
  - DOMAIN-SUFFIX,minisite.letv.com,AD-BAN
  - DOMAIN-SUFFIX,n.mark.letv.com,AD-BAN
  - DOMAIN-SUFFIX,pro.hoye.letv.com,AD-BAN
  - DOMAIN-SUFFIX,pro.letv.com,AD-BAN
  - DOMAIN-SUFFIX,stat.letv.com,AD-BAN
  - DOMAIN-SUFFIX,static.app.m.letv.com,AD-BAN
  - DOMAIN-SUFFIX,click.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,da.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,da.mgtv.com,AD-BAN
  - DOMAIN-SUFFIX,log.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,log.v2.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,p2.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,res.hunantv.com,AD-BAN
  - DOMAIN-SUFFIX,888.tv.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,adnet.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,ads.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,aty.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,aty.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,bd.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,click.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,click2.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,ctr.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,epro.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,epro.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,go.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,golden1.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,golden1.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,hui.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,inte.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,inte.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,inte.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,lm.tv.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,lu.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,pb.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,push.tv.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,pv.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,pv.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,pv.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,theta.sogoucdn.com,AD-BAN
  - DOMAIN-SUFFIX,um.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,uranus.sogou.com,AD-BAN
  - DOMAIN-SUFFIX,uranus.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,wan.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,wl.hd.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,yule.sohu.com,AD-BAN
  - DOMAIN-SUFFIX,afp.pplive.com,AD-BAN
  - DOMAIN-SUFFIX,app.aplus.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,as.aplus.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,asimgs.pplive.cn,AD-BAN
  - DOMAIN-SUFFIX,de.as.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,jp.as.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,pp2.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,stat.pptv.com,AD-BAN
  - DOMAIN-SUFFIX,btrace.video.qq.com,AD-BAN
  - DOMAIN-SUFFIX,c.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,dp3.qq.com,AD-BAN
  - DOMAIN-SUFFIX,livep.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,lives.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,livew.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,mcgi.v.qq.com,AD-BAN
  - DOMAIN-SUFFIX,mdevstat.qqlive.qq.com,AD-BAN
  - DOMAIN-SUFFIX,omgmta1.qq.com,AD-BAN
  - DOMAIN-SUFFIX,p.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,rcgi.video.qq.com,AD-BAN
  - DOMAIN-SUFFIX,t.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,u.l.qq.com,AD-BAN
  - DOMAIN-SUFFIX,a-dxk.play.api.3g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,actives.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ad.api.3g.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,ad.api.3g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ad.api.mobile.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ad.mobile.youku.com,AD-BAN
  - DOMAIN-SUFFIX,adcontrol.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,adplay.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,b.smartvideo.youku.com,AD-BAN
  - DOMAIN-SUFFIX,c.yes.youku.com,AD-BAN
  - DOMAIN-SUFFIX,dev-push.m.youku.com,AD-BAN
  - DOMAIN-SUFFIX,dl.g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,dmapp.youku.com,AD-BAN
  - DOMAIN-SUFFIX,e.stat.ykimg.com,AD-BAN
  - DOMAIN-SUFFIX,gamex.mobile.youku.com,AD-BAN
  - DOMAIN-SUFFIX,goods.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,hudong.pl.youku.com,AD-BAN
  - DOMAIN-SUFFIX,hz.youku.com,AD-BAN
  - DOMAIN-SUFFIX,iwstat.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,iyes.youku.com,AD-BAN
  - DOMAIN-SUFFIX,l.ykimg.com,AD-BAN
  - DOMAIN-SUFFIX,l.youku.com,AD-BAN
  - DOMAIN-SUFFIX,lstat.youku.com,AD-BAN
  - DOMAIN-SUFFIX,lvip.youku.com,AD-BAN
  - DOMAIN-SUFFIX,mobilemsg.youku.com,AD-BAN
  - DOMAIN-SUFFIX,msg.youku.com,AD-BAN
  - DOMAIN-SUFFIX,myes.youku.com,AD-BAN
  - DOMAIN-SUFFIX,nstat.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,p-log.ykimg.com,AD-BAN
  - DOMAIN-SUFFIX,p.l.ykimg.com,AD-BAN
  - DOMAIN-SUFFIX,p.l.youku.com,AD-BAN
  - DOMAIN-SUFFIX,passport-log.youku.com,AD-BAN
  - DOMAIN-SUFFIX,push.m.youku.com,AD-BAN
  - DOMAIN-SUFFIX,r.l.youku.com,AD-BAN
  - DOMAIN-SUFFIX,s.p.youku.com,AD-BAN
  - DOMAIN-SUFFIX,sdk.m.youku.com,AD-BAN
  - DOMAIN-SUFFIX,stat.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,stat.youku.com,AD-BAN
  - DOMAIN-SUFFIX,stats.tudou.com,AD-BAN
  - DOMAIN-SUFFIX,store.tv.api.3g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,store.xl.api.3g.youku.com,AD-BAN
  - DOMAIN-SUFFIX,tdrec.youku.com,AD-BAN
  - DOMAIN-SUFFIX,test.ott.youku.com,AD-BAN
  - DOMAIN-SUFFIX,v.l.youku.com,AD-BAN
  - DOMAIN-SUFFIX,val.api.youku.com,AD-BAN
  - DOMAIN-SUFFIX,wan.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ykatr.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ykrec.youku.com,AD-BAN
  - DOMAIN-SUFFIX,ykrectab.youku.com,AD-BAN
  - IP-CIDR,117.177.248.17/32,AD-BAN,no-resolve
  - IP-CIDR,117.177.248.41/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.176.139/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.176.176/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.180/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.182/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.184/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.43/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.47/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.177.80/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.182.101/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.182.102/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.182.11/32,AD-BAN,no-resolve
  - IP-CIDR,223.87.182.52/32,AD-BAN,no-resolve
  - DOMAIN-SUFFIX,azabu-u.ac.jp,AD-BAN
  - DOMAIN-SUFFIX,couchcoaster.jp,AD-BAN
  - DOMAIN-SUFFIX,delivery.dmkt-sp.jp,AD-BAN
  - DOMAIN-SUFFIX,ehg-youtube.hitbox.com,AD-BAN
  - DOMAIN-SUFFIX,nichibenren.or.jp,AD-BAN
  - DOMAIN-SUFFIX,nicorette.co.kr,AD-BAN
  - DOMAIN-SUFFIX,ssl-youtube.2cnt.net,AD-BAN
  - DOMAIN-SUFFIX,youtube.112.2o7.net,AD-BAN
  - DOMAIN-SUFFIX,youtube.2cnt.net,AD-BAN
  - DOMAIN-SUFFIX,acsystem.wasu.tv,AD-BAN
  - DOMAIN-SUFFIX,ads.cdn.tvb.com,AD-BAN
  - DOMAIN-SUFFIX,ads.wasu.tv,AD-BAN
  - DOMAIN-SUFFIX,afp.wasu.tv,AD-BAN
  - DOMAIN-SUFFIX,c.algovid.com,AD-BAN
  - DOMAIN-SUFFIX,gg.jtertp.com,AD-BAN
  - DOMAIN-SUFFIX,gridsum-vd.cntv.cn,AD-BAN
  - DOMAIN-SUFFIX,kwflvcdn.000dn.com,AD-BAN
  - DOMAIN-SUFFIX,logstat.t.sfht.com,AD-BAN
  - DOMAIN-SUFFIX,match.rtbidder.net,AD-BAN
  - DOMAIN-SUFFIX,n-st.vip.com,AD-BAN
  - DOMAIN-SUFFIX,pop.uusee.com,AD-BAN
  - DOMAIN-SUFFIX,static.duoshuo.com,AD-BAN
  - DOMAIN-SUFFIX,t.cr-nielsen.com,AD-BAN
  - DOMAIN-SUFFIX,terren.cntv.cn,AD-BAN
  - DOMAIN-SUFFIX,1.win7china.com,AD-BAN
  - DOMAIN-SUFFIX,168.it168.com,AD-BAN
  - DOMAIN-SUFFIX,2.win7china.com,AD-BAN
  - DOMAIN-SUFFIX,801.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,801.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,803.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,803.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,806.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,806.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,808.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,808.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,92x.tumblr.com,AD-BAN
  - DOMAIN-SUFFIX,a1.itc.cn,AD-BAN
  - DOMAIN-SUFFIX,ad-channel.wikawika.xyz,AD-BAN
  - DOMAIN-SUFFIX,ad-display.wikawika.xyz,AD-BAN
  - DOMAIN-SUFFIX,ad.12306.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.3.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.95306.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.caiyunapp.com,AD-BAN
  - DOMAIN-SUFFIX,ad.cctv.com,AD-BAN
  - DOMAIN-SUFFIX,ad.cmvideo.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.csdn.net,AD-BAN
  - DOMAIN-SUFFIX,ad.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,ad.house365.com,AD-BAN
  - DOMAIN-SUFFIX,ad.thepaper.cn,AD-BAN
  - DOMAIN-SUFFIX,ad.unimhk.com,AD-BAN
  - DOMAIN-SUFFIX,adadmin.house365.com,AD-BAN
  - DOMAIN-SUFFIX,adhome.1fangchan.com,AD-BAN
  - DOMAIN-SUFFIX,adm.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,ads.csdn.net,AD-BAN
  - DOMAIN-SUFFIX,ads.feedly.com,AD-BAN
  - DOMAIN-SUFFIX,ads.genieessp.com,AD-BAN
  - DOMAIN-SUFFIX,ads.house365.com,AD-BAN
  - DOMAIN-SUFFIX,ads.linkedin.com,AD-BAN
  - DOMAIN-SUFFIX,adshownew.it168.com,AD-BAN
  - DOMAIN-SUFFIX,adv.ccb.com,AD-BAN
  - DOMAIN-SUFFIX,advert.api.thejoyrun.com,AD-BAN
  - DOMAIN-SUFFIX,analytics.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,api-deal.kechenggezi.com,AD-BAN
  - DOMAIN-SUFFIX,api-z.weidian.com,AD-BAN
  - DOMAIN-SUFFIX,app-monitor.ele.me,AD-BAN
  - DOMAIN-SUFFIX,bat.bing.com,AD-BAN
  - DOMAIN-SUFFIX,bd1.52che.com,AD-BAN
  - DOMAIN-SUFFIX,bd2.52che.com,AD-BAN
  - DOMAIN-SUFFIX,bdj.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,bdj.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,beacon.tingyun.com,AD-BAN
  - DOMAIN-SUFFIX,cdn.jiuzhilan.com,AD-BAN
  - DOMAIN-SUFFIX,click.cheshi-img.com,AD-BAN
  - DOMAIN-SUFFIX,click.cheshi.com,AD-BAN
  - DOMAIN-SUFFIX,click.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,click.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,click.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,client-api.ele.me,AD-BAN
  - DOMAIN-SUFFIX,collector.githubapp.com,AD-BAN
  - DOMAIN-SUFFIX,counter.csdn.net,AD-BAN
  - DOMAIN-SUFFIX,d0.xcar.com.cn,AD-BAN
  - DOMAIN-SUFFIX,de.soquair.com,AD-BAN
  - DOMAIN-SUFFIX,dol.tianya.cn,AD-BAN
  - DOMAIN-SUFFIX,dol.tianyaui.cn,AD-BAN
  - DOMAIN-SUFFIX,dw.xcar.com.cn,AD-BAN
  - DOMAIN-SUFFIX,e.nexac.com,AD-BAN
  - DOMAIN-SUFFIX,eq.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,exp.17wo.cn,AD-BAN
  - DOMAIN-SUFFIX,game.51yund.com,AD-BAN
  - DOMAIN-SUFFIX,ganjituiguang.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,grand.ele.me,AD-BAN
  - DOMAIN-SUFFIX,hosting.miarroba.info,AD-BAN
  - DOMAIN-SUFFIX,iadsdk.apple.com,AD-BAN
  - DOMAIN-SUFFIX,image.gentags.com,AD-BAN
  - DOMAIN-SUFFIX,its-dori.tumblr.com,AD-BAN
  - DOMAIN-SUFFIX,log.outbrain.com,AD-BAN
  - DOMAIN-SUFFIX,m.12306media.com,AD-BAN
  - DOMAIN-SUFFIX,media.cheshi-img.com,AD-BAN
  - DOMAIN-SUFFIX,media.cheshi.com,AD-BAN
  - DOMAIN-SUFFIX,mobile-pubt.ele.me,AD-BAN
  - DOMAIN-SUFFIX,mobileads.msn.com,AD-BAN
  - DOMAIN-SUFFIX,n.cosbot.cn,AD-BAN
  - DOMAIN-SUFFIX,newton-api.ele.me,AD-BAN
  - DOMAIN-SUFFIX,ozone.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,pdl.gionee.com,AD-BAN
  - DOMAIN-SUFFIX,pica-juicy.picacomic.com,AD-BAN
  - DOMAIN-SUFFIX,pixel.wp.com,AD-BAN
  - DOMAIN-SUFFIX,pub.mop.com,AD-BAN
  - DOMAIN-SUFFIX,push.wandoujia.com,AD-BAN
  - DOMAIN-SUFFIX,pv.cheshi-img.com,AD-BAN
  - DOMAIN-SUFFIX,pv.cheshi.com,AD-BAN
  - DOMAIN-SUFFIX,pv.xcar.com.cn,AD-BAN
  - DOMAIN-SUFFIX,qdp.qidian.com,AD-BAN
  - DOMAIN-SUFFIX,res.gwifi.com.cn,AD-BAN
  - DOMAIN-SUFFIX,ssp.kssws.ks-cdn.com,AD-BAN
  - DOMAIN-SUFFIX,sta.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,stat.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,stat.it168.com,AD-BAN
  - DOMAIN-SUFFIX,stats.chinaz.com,AD-BAN
  - DOMAIN-SUFFIX,stats.developingperspective.com,AD-BAN
  - DOMAIN-SUFFIX,track.hujiang.com,AD-BAN
  - DOMAIN-SUFFIX,tracker.yhd.com,AD-BAN
  - DOMAIN-SUFFIX,tralog.ganji.com,AD-BAN
  - DOMAIN-SUFFIX,up.qingdaonews.com,AD-BAN
  - DOMAIN-SUFFIX,vaserviece.10jqka.com.cn,AD-BAN
  - DOMAIN-SUFFIX,265.com,DC
  - DOMAIN-SUFFIX,2mdn.net,DC
  - DOMAIN-SUFFIX,alt1-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt2-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt3-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt4-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt5-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt6-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt7-mtalk.google.com,DC
  - DOMAIN-SUFFIX,alt8-mtalk.google.com,DC
  - DOMAIN-SUFFIX,app-measurement.com,DC
  - DOMAIN-SUFFIX,cache.pack.google.com,DC
  - DOMAIN-SUFFIX,clickserve.dartsearch.net,DC
  - DOMAIN-SUFFIX,crl.pki.goog,DC
  - DOMAIN-SUFFIX,dl.google.com,DC
  - DOMAIN-SUFFIX,dl.l.google.com,DC
  - DOMAIN-SUFFIX,googletagmanager.com,DC
  - DOMAIN-SUFFIX,googletagservices.com,DC
  - DOMAIN-SUFFIX,gtm.oasisfeng.com,DC
  - DOMAIN-SUFFIX,mtalk.google.com,DC
  - DOMAIN-SUFFIX,ocsp.pki.goog,DC
  - DOMAIN-SUFFIX,recaptcha.net,DC
  - DOMAIN-SUFFIX,safebrowsing-cache.google.com,DC
  - DOMAIN-SUFFIX,settings.crashlytics.com,DC
  - DOMAIN-SUFFIX,ssl-google-analytics.l.google.com,DC
  - DOMAIN-SUFFIX,toolbarqueries.google.com,DC
  - DOMAIN-SUFFIX,tools.google.com,DC
  - DOMAIN-SUFFIX,tools.l.google.com,DC
  - DOMAIN-SUFFIX,www-googletagmanager.l.google.com,DC
  - DOMAIN,csgo.wmsj.cn,DC
  - DOMAIN,dl.steam.clngaa.com,DC
  - DOMAIN,dl.steam.ksyna.com,DC
  - DOMAIN,dota2.wmsj.cn,DC
  - DOMAIN,st.dl.bscstorage.net,DC
  - DOMAIN,st.dl.eccdnx.com,DC
  - DOMAIN,st.dl.pinyuncloud.com,DC
  - DOMAIN,steampipe.steamcontent.tnkjmec.com,DC
  - DOMAIN,steampowered.com.8686c.com,DC
  - DOMAIN,steamstatic.com.8686c.com,DC
  - DOMAIN,wmsjsteam.com,DC
  - DOMAIN,xz.pphimalayanrt.com,DC
  - DOMAIN-SUFFIX,cm.steampowered.com,DC
  - DOMAIN-SUFFIX,steamchina.com,DC
  - DOMAIN-SUFFIX,steamcontent.com,DC
  - DOMAIN-SUFFIX,steamusercontent.com,DC
  - DOMAIN-SUFFIX,163yun.com,DC
  - DOMAIN-SUFFIX,api.iplay.163.com,DC
  - DOMAIN-SUFFIX,hz.netease.com,DC
  - DOMAIN-SUFFIX,mam.netease.com,DC
  - DOMAIN-SUFFIX,music.163.com,DC
  - DOMAIN-SUFFIX,music.163.com.163jiasu.com,DC
  - IP-CIDR,39.105.63.80/32,DC,no-resolve
  - IP-CIDR,39.105.175.128/32,DC,no-resolve
  - IP-CIDR,45.254.48.1/32,DC,no-resolve
  - IP-CIDR,47.100.127.239/32,DC,no-resolve
  - IP-CIDR,59.111.19.33/32,DC,no-resolve
  - IP-CIDR,59.111.21.14/31,DC,no-resolve
  - IP-CIDR,59.111.160.195/32,DC,no-resolve
  - IP-CIDR,59.111.160.197/32,DC,no-resolve
  - IP-CIDR,59.111.179.214/32,DC,no-resolve
  - IP-CIDR,59.111.181.35/32,DC,no-resolve
  - IP-CIDR,59.111.181.38/32,DC,no-resolve
  - IP-CIDR,59.111.181.60/32,DC,no-resolve
  - IP-CIDR,59.111.238.29/32,DC,no-resolve
  - IP-CIDR,101.71.154.241/32,DC,no-resolve
  - IP-CIDR,103.126.92.132/31,DC,no-resolve
  - IP-CIDR,103.126.92.132/32,DC,no-resolve
  - IP-CIDR,103.126.92.133/32,DC,no-resolve
  - IP-CIDR,112.13.119.17/32,DC,no-resolve
  - IP-CIDR,112.13.119.18/32,DC,no-resolve
  - IP-CIDR,112.13.122.1/32,DC,no-resolve
  - IP-CIDR,112.13.122.4/32,DC,no-resolve
  - IP-CIDR,115.236.118.33/32,DC,no-resolve
  - IP-CIDR,115.236.118.34/32,DC,no-resolve
  - IP-CIDR,115.236.121.1/32,DC,no-resolve
  - IP-CIDR,115.236.121.4/32,DC,no-resolve
  - IP-CIDR,118.24.63.156/32,DC,no-resolve
  - IP-CIDR,182.92.170.253/32,DC,no-resolve
  - IP-CIDR,193.112.159.225/32,DC,no-resolve
  - IP-CIDR,223.252.199.66/31,DC,no-resolve
  - IP-CIDR,223.252.199.66/32,DC,no-resolve
  - IP-CIDR,223.252.199.67/32,DC,no-resolve
  - DOMAIN,bahamut.akamaized.net,BILI
  - DOMAIN,gamer-cds.cdn.hinet.net,BILI
  - DOMAIN,gamer2-cds.cdn.hinet.net,BILI
  - DOMAIN-SUFFIX,bahamut.com.tw,BILI
  - DOMAIN-SUFFIX,gamer.com.tw,BILI
  - DOMAIN,p-bstarstatic.akamaized.net,BILI
  - DOMAIN,p.bstarstatic.com,BILI
  - DOMAIN,upos-bstar-mirrorakam.akamaized.net,BILI
  - DOMAIN,upos-bstar1-mirrorakam.akamaized.net,BILI
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,BILI
  - DOMAIN-SUFFIX,acgvideo.com,BILI
  - DOMAIN-SUFFIX,bilibili.com,BILI
  - DOMAIN-SUFFIX,bilibili.tv,BILI
  - IP-CIDR,45.43.32.234/32,BILI,no-resolve
  - IP-CIDR,103.151.150.0/23,BILI,no-resolve
  - IP-CIDR,119.29.29.29/32,BILI,no-resolve
  - IP-CIDR,128.1.62.200/32,BILI,no-resolve
  - IP-CIDR,128.1.62.201/32,BILI,no-resolve
  - IP-CIDR,150.116.92.250/32,BILI,no-resolve
  - IP-CIDR,164.52.33.178/32,BILI,no-resolve
  - IP-CIDR,164.52.33.182/32,BILI,no-resolve
  - IP-CIDR,164.52.76.18/32,BILI,no-resolve
  - IP-CIDR,203.107.1.33/32,BILI,no-resolve
  - IP-CIDR,203.107.1.34/32,BILI,no-resolve
  - IP-CIDR,203.107.1.65/32,BILI,no-resolve
  - IP-CIDR,203.107.1.66/32,BILI,no-resolve
  - DOMAIN,apiintl.biliapi.net,BILI
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,BILI
  - DOMAIN-SUFFIX,acg.tv,BILI
  - DOMAIN-SUFFIX,acgvideo.com,BILI
  - DOMAIN-SUFFIX,b23.tv,BILI
  - DOMAIN-SUFFIX,bigfun.cn,BILI
  - DOMAIN-SUFFIX,bigfunapp.cn,BILI
  - DOMAIN-SUFFIX,biliapi.com,BILI
  - DOMAIN-SUFFIX,biliapi.net,BILI
  - DOMAIN-SUFFIX,bilibili.co,BILI
  - DOMAIN-SUFFIX,bilibili.com,BILI
  - DOMAIN-SUFFIX,bilibili.tv,BILI
  - DOMAIN-SUFFIX,biligame.com,BILI
  - DOMAIN-SUFFIX,biligame.net,BILI
  - DOMAIN-SUFFIX,biliintl.co,BILI
  - DOMAIN-SUFFIX,bilivideo.cn,BILI
  - DOMAIN-SUFFIX,bilivideo.com,BILI
  - DOMAIN-SUFFIX,hdslb.com,BILI
  - DOMAIN-SUFFIX,im9.com,BILI
  - DOMAIN-SUFFIX,smtcdns.net,BILI
  - DOMAIN,apiintl.biliapi.net,BILI
  - DOMAIN,upos-hz-mirrorakam.akamaized.net,BILI
  - DOMAIN-SUFFIX,acg.tv,BILI
  - DOMAIN-SUFFIX,acgvideo.com,BILI
  - DOMAIN-SUFFIX,b23.tv,BILI
  - DOMAIN-SUFFIX,bigfun.cn,BILI
  - DOMAIN-SUFFIX,bigfunapp.cn,BILI
  - DOMAIN-SUFFIX,biliapi.com,BILI
  - DOMAIN-SUFFIX,biliapi.net,BILI
  - DOMAIN-SUFFIX,bilibili.com,BILI
  - DOMAIN-SUFFIX,bilibili.tv,BILI
  - DOMAIN-SUFFIX,biligame.com,BILI
  - DOMAIN-SUFFIX,biligame.net,BILI
  - DOMAIN-SUFFIX,bilivideo.cn,BILI
  - DOMAIN-SUFFIX,bilivideo.com,BILI
  - DOMAIN-SUFFIX,hdslb.com,BILI
  - DOMAIN-SUFFIX,im9.com,BILI
  - DOMAIN-SUFFIX,smtcdns.net,BILI
  - DOMAIN,intel-cache.m.iqiyi.com,BILI
  - DOMAIN,intel-cache.video.iqiyi.com,BILI
  - DOMAIN,intl-rcd.iqiyi.com,BILI
  - DOMAIN,intl-subscription.iqiyi.com,BILI
  - DOMAIN-SUFFIX,inter.iqiyi.com,BILI
  - DOMAIN-SUFFIX,inter.ptqy.gitv.tv,BILI
  - DOMAIN-SUFFIX,intl.iqiyi.com,BILI
  - DOMAIN-SUFFIX,iq.com,BILI
  - IP-CIDR,23.40.241.251/32,BILI,no-resolve
  - IP-CIDR,23.40.242.10/32,BILI,no-resolve
  - IP-CIDR,103.44.56.0/22,BILI,no-resolve
  - IP-CIDR,118.26.32.0/23,BILI,no-resolve
  - IP-CIDR,118.26.120.0/24,BILI,no-resolve
  - IP-CIDR,223.119.62.225/28,BILI,no-resolve
  - DOMAIN-SUFFIX,api.mob.app.letv.com,BILI
  - DOMAIN-SUFFIX,v.smtcdns.com,BILI
  - DOMAIN-SUFFIX,vv.video.qq.com,BILI
  - DOMAIN-SUFFIX,youku.com,BILI
  - IP-CIDR,106.11.0.0/16,BILI,no-resolve
  - DOMAIN-SUFFIX,zuoyebang.com,DC
  - DOMAIN-SUFFIX,steampy.com,DC
  - DOMAIN-SUFFIX,qq.com,DC
  - DOMAIN-SUFFIX,gushiwen.cn,DC
  - DOMAIN-SUFFIX,13th.tech,DC
  - DOMAIN-SUFFIX,423down.com,DC
  - DOMAIN-SUFFIX,bokecc.com,DC
  - DOMAIN-SUFFIX,chaipip.com,DC
  - DOMAIN-SUFFIX,chinaplay.store,DC
  - DOMAIN-SUFFIX,hrtsea.com,DC
  - DOMAIN-SUFFIX,kaikeba.com,DC
  - DOMAIN-SUFFIX,laomo.me,DC
  - DOMAIN-SUFFIX,mpyit.com,DC
  - DOMAIN-SUFFIX,msftconnecttest.com,DC
  - DOMAIN-SUFFIX,msftncsi.com,DC
  - DOMAIN-SUFFIX,qupu123.com,DC
  - DOMAIN-SUFFIX,pdfwifi.com,DC
  - DOMAIN-SUFFIX,zhenguanyu.biz,DC
  - DOMAIN-SUFFIX,zhenguanyu.com,DC
  - DOMAIN-SUFFIX,snapdrop.net,DC
  - DOMAIN-SUFFIX,tebex.io,DC
  - DOMAIN-SUFFIX,cn,DC
  - DOMAIN-SUFFIX,xn--fiqs8s,DC
  - DOMAIN-SUFFIX,xn--55qx5d,DC
  - DOMAIN-SUFFIX,xn--io0a7i,DC
  - DOMAIN-KEYWORD,360buy,DC
  - DOMAIN-KEYWORD,alicdn,DC
  - DOMAIN-KEYWORD,alimama,DC
  - DOMAIN-KEYWORD,alipay,DC
  - DOMAIN-KEYWORD,appzapp,DC
  - DOMAIN-KEYWORD,baidupcs,DC
  - DOMAIN-KEYWORD,bilibili,DC
  - DOMAIN-KEYWORD,ccgslb,DC
  - DOMAIN-KEYWORD,chinacache,DC
  - DOMAIN-KEYWORD,duobao,DC
  - DOMAIN-KEYWORD,jdpay,DC
  - DOMAIN-KEYWORD,moke,DC
  - DOMAIN-KEYWORD,qhimg,DC
  - DOMAIN-KEYWORD,vpimg,DC
  - DOMAIN-KEYWORD,xiami,DC
  - DOMAIN-KEYWORD,xiaomi,DC
  - DOMAIN-SUFFIX,360.com,DC
  - DOMAIN-SUFFIX,360kuai.com,DC
  - DOMAIN-SUFFIX,360safe.com,DC
  - DOMAIN-SUFFIX,dhrest.com,DC
  - DOMAIN-SUFFIX,qhres.com,DC
  - DOMAIN-SUFFIX,qhstatic.com,DC
  - DOMAIN-SUFFIX,qhupdate.com,DC
  - DOMAIN-SUFFIX,so.com,DC
  - DOMAIN-SUFFIX,4399.com,DC
  - DOMAIN-SUFFIX,4399pk.com,DC
  - DOMAIN-SUFFIX,5054399.com,DC
  - DOMAIN-SUFFIX,img4399.com,DC
  - DOMAIN-SUFFIX,58.com,DC
  - DOMAIN-SUFFIX,1688.com,DC
  - DOMAIN-SUFFIX,aliapp.org,DC
  - DOMAIN-SUFFIX,alibaba.com,DC
  - DOMAIN-SUFFIX,alibabacloud.com,DC
  - DOMAIN-SUFFIX,alibabausercontent.com,DC
  - DOMAIN-SUFFIX,alicdn.com,DC
  - DOMAIN-SUFFIX,alicloudccp.com,DC
  - DOMAIN-SUFFIX,aliexpress.com,DC
  - DOMAIN-SUFFIX,aliimg.com,DC
  - DOMAIN-SUFFIX,alikunlun.com,DC
  - DOMAIN-SUFFIX,alipay.com,DC
  - DOMAIN-SUFFIX,alipayobjects.com,DC
  - DOMAIN-SUFFIX,alisoft.com,DC
  - DOMAIN-SUFFIX,aliyun.com,DC
  - DOMAIN-SUFFIX,aliyuncdn.com,DC
  - DOMAIN-SUFFIX,aliyuncs.com,DC
  - DOMAIN-SUFFIX,aliyundrive.com,DC
  - DOMAIN-SUFFIX,aliyundrive.net,DC
  - DOMAIN-SUFFIX,amap.com,DC
  - DOMAIN-SUFFIX,autonavi.com,DC
  - DOMAIN-SUFFIX,dingtalk.com,DC
  - DOMAIN-SUFFIX,ele.me,DC
  - DOMAIN-SUFFIX,hichina.com,DC
  - DOMAIN-SUFFIX,mmstat.com,DC
  - DOMAIN-SUFFIX,mxhichina.com,DC
  - DOMAIN-SUFFIX,soku.com,DC
  - DOMAIN-SUFFIX,taobao.com,DC
  - DOMAIN-SUFFIX,taobaocdn.com,DC
  - DOMAIN-SUFFIX,tbcache.com,DC
  - DOMAIN-SUFFIX,tbcdn.com,DC
  - DOMAIN-SUFFIX,tmall.com,DC
  - DOMAIN-SUFFIX,tmall.hk,DC
  - DOMAIN-SUFFIX,ucweb.com,DC
  - DOMAIN-SUFFIX,xiami.com,DC
  - DOMAIN-SUFFIX,xiami.net,DC
  - DOMAIN-SUFFIX,ykimg.com,DC
  - DOMAIN-SUFFIX,youku.com,DC
  - DOMAIN-SUFFIX,baidu.com,DC
  - DOMAIN-SUFFIX,baidubcr.com,DC
  - DOMAIN-SUFFIX,baidupcs.com,DC
  - DOMAIN-SUFFIX,baidustatic.com,DC
  - DOMAIN-SUFFIX,bcebos.com,DC
  - DOMAIN-SUFFIX,bdimg.com,DC
  - DOMAIN-SUFFIX,bdstatic.com,DC
  - DOMAIN-SUFFIX,bdurl.net,DC
  - DOMAIN-SUFFIX,hao123.com,DC
  - DOMAIN-SUFFIX,hao123img.com,DC
  - DOMAIN-SUFFIX,jomodns.com,DC
  - DOMAIN-SUFFIX,yunjiasu-cdn.net,DC
  - DOMAIN-SUFFIX,acg.tv,DC
  - DOMAIN-SUFFIX,acgvideo.com,DC
  - DOMAIN-SUFFIX,b23.tv,DC
  - DOMAIN-SUFFIX,bigfun.cn,DC
  - DOMAIN-SUFFIX,bigfunapp.cn,DC
  - DOMAIN-SUFFIX,biliapi.com,DC
  - DOMAIN-SUFFIX,biliapi.net,DC
  - DOMAIN-SUFFIX,bilibili.com,DC
  - DOMAIN-SUFFIX,bilibili.co,DC
  - DOMAIN-SUFFIX,biliintl.co,DC
  - DOMAIN-SUFFIX,biligame.com,DC
  - DOMAIN-SUFFIX,biligame.net,DC
  - DOMAIN-SUFFIX,bilivideo.com,DC
  - DOMAIN-SUFFIX,bilivideo.cn,DC
  - DOMAIN-SUFFIX,hdslb.com,DC
  - DOMAIN-SUFFIX,im9.com,DC
  - DOMAIN-SUFFIX,smtcdns.net,DC
  - DOMAIN-SUFFIX,amemv.com,DC
  - DOMAIN-SUFFIX,bdxiguaimg.com,DC
  - DOMAIN-SUFFIX,bdxiguastatic.com,DC
  - DOMAIN-SUFFIX,byted-static.com,DC
  - DOMAIN-SUFFIX,bytedance.com,DC
  - DOMAIN-SUFFIX,bytedance.net,DC
  - DOMAIN-SUFFIX,bytedns.net,DC
  - DOMAIN-SUFFIX,bytednsdoc.com,DC
  - DOMAIN-SUFFIX,bytegoofy.com,DC
  - DOMAIN-SUFFIX,byteimg.com,DC
  - DOMAIN-SUFFIX,bytescm.com,DC
  - DOMAIN-SUFFIX,bytetos.com,DC
  - DOMAIN-SUFFIX,bytexservice.com,DC
  - DOMAIN-SUFFIX,douyin.com,DC
  - DOMAIN-SUFFIX,douyincdn.com,DC
  - DOMAIN-SUFFIX,douyinpic.com,DC
  - DOMAIN-SUFFIX,douyinstatic.com,DC
  - DOMAIN-SUFFIX,douyinvod.com,DC
  - DOMAIN-SUFFIX,feelgood.cn,DC
  - DOMAIN-SUFFIX,feiliao.com,DC
  - DOMAIN-SUFFIX,gifshow.com,DC
  - DOMAIN-SUFFIX,huoshan.com,DC
  - DOMAIN-SUFFIX,huoshanzhibo.com,DC
  - DOMAIN-SUFFIX,ibytedapm.com,DC
  - DOMAIN-SUFFIX,iesdouyin.com,DC
  - DOMAIN-SUFFIX,ixigua.com,DC
  - DOMAIN-SUFFIX,kspkg.com,DC
  - DOMAIN-SUFFIX,pstatp.com,DC
  - DOMAIN-SUFFIX,snssdk.com,DC
  - DOMAIN-SUFFIX,toutiao.com,DC
  - DOMAIN-SUFFIX,toutiao13.com,DC
  - DOMAIN-SUFFIX,toutiaoapi.com,DC
  - DOMAIN-SUFFIX,toutiaocdn.com,DC
  - DOMAIN-SUFFIX,toutiaocdn.net,DC
  - DOMAIN-SUFFIX,toutiaocloud.com,DC
  - DOMAIN-SUFFIX,toutiaohao.com,DC
  - DOMAIN-SUFFIX,toutiaohao.net,DC
  - DOMAIN-SUFFIX,toutiaoimg.com,DC
  - DOMAIN-SUFFIX,toutiaopage.com,DC
  - DOMAIN-SUFFIX,wukong.com,DC
  - DOMAIN-SUFFIX,zijieapi.com,DC
  - DOMAIN-SUFFIX,zijieimg.com,DC
  - DOMAIN-SUFFIX,zjbyte.com,DC
  - DOMAIN-SUFFIX,zjcdn.com,DC
  - DOMAIN-SUFFIX,cctv.com,DC
  - DOMAIN-SUFFIX,cctvpic.com,DC
  - DOMAIN-SUFFIX,livechina.com,DC
  - DOMAIN-SUFFIX,21cn.com,DC
  - DOMAIN-SUFFIX,didialift.com,DC
  - DOMAIN-SUFFIX,didiglobal.com,DC
  - DOMAIN-SUFFIX,udache.com,DC
  - DOMAIN-SUFFIX,bytefcdnrd.com,DC
  - DOMAIN-SUFFIX,edgesrv.com,DC
  - DOMAIN-SUFFIX,douyu.com,DC
  - DOMAIN-SUFFIX,douyu.tv,DC
  - DOMAIN-SUFFIX,douyuscdn.com,DC
  - DOMAIN-SUFFIX,douyutv.com,DC
  - DOMAIN-SUFFIX,epicgames.com,DC
  - DOMAIN-SUFFIX,epicgames.dev,DC
  - DOMAIN-SUFFIX,helpshift.com,DC
  - DOMAIN-SUFFIX,paragon.com,DC
  - DOMAIN-SUFFIX,unrealengine.com,DC
  - DOMAIN-SUFFIX,dbankcdn.com,DC
  - DOMAIN-SUFFIX,hc-cdn.com,DC
  - DOMAIN-SUFFIX,hicloud.com,DC
  - DOMAIN-SUFFIX,hihonor.com,DC
  - DOMAIN-SUFFIX,huawei.com,DC
  - DOMAIN-SUFFIX,huaweicloud.com,DC
  - DOMAIN-SUFFIX,huaweishop.net,DC
  - DOMAIN-SUFFIX,hwccpc.com,DC
  - DOMAIN-SUFFIX,vmall.com,DC
  - DOMAIN-SUFFIX,vmallres.com,DC
  - DOMAIN-SUFFIX,allawnfs.com,DC
  - DOMAIN-SUFFIX,allawno.com,DC
  - DOMAIN-SUFFIX,allawntech.com,DC
  - DOMAIN-SUFFIX,coloros.com,DC
  - DOMAIN-SUFFIX,heytap.com,DC
  - DOMAIN-SUFFIX,heytapcs.com,DC
  - DOMAIN-SUFFIX,heytapdownload.com,DC
  - DOMAIN-SUFFIX,heytapimage.com,DC
  - DOMAIN-SUFFIX,heytapmobi.com,DC
  - DOMAIN-SUFFIX,oppo.com,DC
  - DOMAIN-SUFFIX,oppoer.me,DC
  - DOMAIN-SUFFIX,oppomobile.com,DC
  - DOMAIN-SUFFIX,iflyink.com,DC
  - DOMAIN-SUFFIX,iflyrec.com,DC
  - DOMAIN-SUFFIX,iflytek.com,DC
  - DOMAIN-SUFFIX,71.am,DC
  - DOMAIN-SUFFIX,71edge.com,DC
  - DOMAIN-SUFFIX,iqiyi.com,DC
  - DOMAIN-SUFFIX,iqiyipic.com,DC
  - DOMAIN-SUFFIX,ppsimg.com,DC
  - DOMAIN-SUFFIX,qiyi.com,DC
  - DOMAIN-SUFFIX,qiyipic.com,DC
  - DOMAIN-SUFFIX,qy.net,DC
  - DOMAIN-SUFFIX,360buy.com,DC
  - DOMAIN-SUFFIX,360buyimg.com,DC
  - DOMAIN-SUFFIX,jcloudcs.com,DC
  - DOMAIN-SUFFIX,jd.com,DC
  - DOMAIN-SUFFIX,jd.hk,DC
  - DOMAIN-SUFFIX,jdcloud.com,DC
  - DOMAIN-SUFFIX,jdpay.com,DC
  - DOMAIN-SUFFIX,paipai.com,DC
  - DOMAIN-SUFFIX,iciba.com,DC
  - DOMAIN-SUFFIX,ksosoft.com,DC
  - DOMAIN-SUFFIX,ksyun.com,DC
  - DOMAIN-SUFFIX,kuaishou.com,DC
  - DOMAIN-SUFFIX,yximgs.com,DC
  - DOMAIN-SUFFIX,meitu.com,DC
  - DOMAIN-SUFFIX,meitudata.com,DC
  - DOMAIN-SUFFIX,meitustat.com,DC
  - DOMAIN-SUFFIX,meipai.com,DC
  - DOMAIN-SUFFIX,le.com,DC
  - DOMAIN-SUFFIX,lecloud.com,DC
  - DOMAIN-SUFFIX,letv.com,DC
  - DOMAIN-SUFFIX,letvcloud.com,DC
  - DOMAIN-SUFFIX,letvimg.com,DC
  - DOMAIN-SUFFIX,letvlive.com,DC
  - DOMAIN-SUFFIX,letvstore.com,DC
  - DOMAIN-SUFFIX,hitv.com,DC
  - DOMAIN-SUFFIX,hunantv.com,DC
  - DOMAIN-SUFFIX,mgtv.com,DC
  - DOMAIN-SUFFIX,duokan.com,DC
  - DOMAIN-SUFFIX,mi-img.com,DC
  - DOMAIN-SUFFIX,mi.com,DC
  - DOMAIN-SUFFIX,miui.com,DC
  - DOMAIN-SUFFIX,xiaomi.com,DC
  - DOMAIN-SUFFIX,xiaomi.net,DC
  - DOMAIN-SUFFIX,xiaomicp.com,DC
  - DOMAIN-SUFFIX,126.com,DC
  - DOMAIN-SUFFIX,126.net,DC
  - DOMAIN-SUFFIX,127.net,DC
  - DOMAIN-SUFFIX,163.com,DC
  - DOMAIN-SUFFIX,163yun.com,DC
  - DOMAIN-SUFFIX,lofter.com,DC
  - DOMAIN-SUFFIX,netease.com,DC
  - DOMAIN-SUFFIX,ydstatic.com,DC
  - DOMAIN-SUFFIX,youdao.com,DC
  - DOMAIN-SUFFIX,pplive.com,DC
  - DOMAIN-SUFFIX,pptv.com,DC
  - DOMAIN-SUFFIX,pinduoduo.com,DC
  - DOMAIN-SUFFIX,yangkeduo.com,DC
  - DOMAIN-SUFFIX,leju.com,DC
  - DOMAIN-SUFFIX,miaopai.com,DC
  - DOMAIN-SUFFIX,sina.com,DC
  - DOMAIN-SUFFIX,sina.com.cn,DC
  - DOMAIN-SUFFIX,sina.cn,DC
  - DOMAIN-SUFFIX,sinaapp.com,DC
  - DOMAIN-SUFFIX,sinaapp.cn,DC
  - DOMAIN-SUFFIX,sinaimg.com,DC
  - DOMAIN-SUFFIX,sinaimg.cn,DC
  - DOMAIN-SUFFIX,weibo.com,DC
  - DOMAIN-SUFFIX,weibo.cn,DC
  - DOMAIN-SUFFIX,weibocdn.com,DC
  - DOMAIN-SUFFIX,weibocdn.cn,DC
  - DOMAIN-SUFFIX,xiaoka.tv,DC
  - DOMAIN-SUFFIX,go2map.com,DC
  - DOMAIN-SUFFIX,sogo.com,DC
  - DOMAIN-SUFFIX,sogou.com,DC
  - DOMAIN-SUFFIX,sogoucdn.com,DC
  - DOMAIN-SUFFIX,sohu-inc.com,DC
  - DOMAIN-SUFFIX,sohu.com,DC
  - DOMAIN-SUFFIX,sohucs.com,DC
  - DOMAIN-SUFFIX,sohuno.com,DC
  - DOMAIN-SUFFIX,sohurdc.com,DC
  - DOMAIN-SUFFIX,v-56.com,DC
  - DOMAIN-SUFFIX,playstation.com,DC
  - DOMAIN-SUFFIX,playstation.net,DC
  - DOMAIN-SUFFIX,playstationnetwork.com,DC
  - DOMAIN-SUFFIX,sony.com,DC
  - DOMAIN-SUFFIX,sonyentertainmentnetwork.com,DC
  - DOMAIN-SUFFIX,cm.steampowered.com,DC
  - DOMAIN-SUFFIX,steamcontent.com,DC
  - DOMAIN-SUFFIX,steamusercontent.com,DC
  - DOMAIN-SUFFIX,steamchina.com,DC
  - DOMAIN,csgo.wmsj.cn,DC
  - DOMAIN,dota2.wmsj.cn,DC
  - DOMAIN,wmsjsteam.com,DC
  - DOMAIN,dl.steam.clngaa.com,DC
  - DOMAIN,dl.steam.ksyna.com,DC
  - DOMAIN,st.dl.bscstorage.net,DC
  - DOMAIN,st.dl.eccdnx.com,DC
  - DOMAIN,st.dl.pinyuncloud.com,DC
  - DOMAIN,xz.pphimalayanrt.com,DC
  - DOMAIN,steampipe.steamcontent.tnkjmec.com,DC
  - DOMAIN,steampowered.com.8686c.com,DC
  - DOMAIN,steamstatic.com.8686c.com,DC
  - DOMAIN-SUFFIX,foxmail.com,DC
  - DOMAIN-SUFFIX,gtimg.com,DC
  - DOMAIN-SUFFIX,idqqimg.com,DC
  - DOMAIN-SUFFIX,igamecj.com,DC
  - DOMAIN-SUFFIX,myapp.com,DC
  - DOMAIN-SUFFIX,myqcloud.com,DC
  - DOMAIN-SUFFIX,qq.com,DC
  - DOMAIN-SUFFIX,qqmail.com,DC
  - DOMAIN-SUFFIX,qqurl.com,DC
  - DOMAIN-SUFFIX,smtcdns.com,DC
  - DOMAIN-SUFFIX,smtcdns.net,DC
  - DOMAIN-SUFFIX,soso.com,DC
  - DOMAIN-SUFFIX,tencent-cloud.net,DC
  - DOMAIN-SUFFIX,tencent.com,DC
  - DOMAIN-SUFFIX,tencentmind.com,DC
  - DOMAIN-SUFFIX,tenpay.com,DC
  - DOMAIN-SUFFIX,wechat.com,DC
  - DOMAIN-SUFFIX,weixin.com,DC
  - DOMAIN-SUFFIX,weiyun.com,DC
  - DOMAIN-SUFFIX,appsimg.com,DC
  - DOMAIN-SUFFIX,appvipshop.com,DC
  - DOMAIN-SUFFIX,vip.com,DC
  - DOMAIN-SUFFIX,vipstatic.com,DC
  - DOMAIN-SUFFIX,ximalaya.com,DC
  - DOMAIN-SUFFIX,xmcdn.com,DC
  - DOMAIN-SUFFIX,00cdn.com,DC
  - DOMAIN-SUFFIX,88cdn.com,DC
  - DOMAIN-SUFFIX,kanimg.com,DC
  - DOMAIN-SUFFIX,kankan.com,DC
  - DOMAIN-SUFFIX,p2cdn.com,DC
  - DOMAIN-SUFFIX,sandai.net,DC
  - DOMAIN-SUFFIX,thundercdn.com,DC
  - DOMAIN-SUFFIX,xunlei.com,DC
  - DOMAIN-SUFFIX,got001.com,DC
  - DOMAIN-SUFFIX,p4pfile.com,DC
  - DOMAIN-SUFFIX,rrys.tv,DC
  - DOMAIN-SUFFIX,rrys2020.com,DC
  - DOMAIN-SUFFIX,yyets.com,DC
  - DOMAIN-SUFFIX,zimuzu.io,DC
  - DOMAIN-SUFFIX,zimuzu.tv,DC
  - DOMAIN-SUFFIX,zmz001.com,DC
  - DOMAIN-SUFFIX,zmz002.com,DC
  - DOMAIN-SUFFIX,zmz003.com,DC
  - DOMAIN-SUFFIX,zmz004.com,DC
  - DOMAIN-SUFFIX,zmz2019.com,DC
  - DOMAIN-SUFFIX,zmzapi.com,DC
  - DOMAIN-SUFFIX,zmzapi.net,DC
  - DOMAIN-SUFFIX,zmzfile.com,DC
  - DOMAIN-SUFFIX,teamviewer.com,DC
  - IP-CIDR,139.220.243.27/32,DC,no-resolve
  - IP-CIDR,172.16.102.56/32,DC,no-resolve
  - IP-CIDR,185.188.32.1/28,DC,no-resolve
  - IP-CIDR,221.226.128.146/32,DC,no-resolve
  - IP-CIDR6,2a0b:b580::/48,DC,no-resolve
  - IP-CIDR6,2a0b:b581::/48,DC,no-resolve
  - IP-CIDR6,2a0b:b582::/48,DC,no-resolve
  - IP-CIDR6,2a0b:b583::/48,DC,no-resolve
  - DOMAIN-SUFFIX,baomitu.com,DC
  - DOMAIN-SUFFIX,bootcss.com,DC
  - DOMAIN-SUFFIX,jiasule.com,DC
  - DOMAIN-SUFFIX,staticfile.org,DC
  - DOMAIN-SUFFIX,upaiyun.com,DC
  - DOMAIN-SUFFIX,doh.pub,DC
  - DOMAIN-SUFFIX,dns.alidns.com,DC
  - DOMAIN-SUFFIX,doh.360.cn,DC
  - IP-CIDR,1.12.12.12/32,DC,no-resolve
  - DOMAIN-SUFFIX,10010.com,DC
  - DOMAIN-SUFFIX,115.com,DC
  - DOMAIN-SUFFIX,12306.com,DC
  - DOMAIN-SUFFIX,17173.com,DC
  - DOMAIN-SUFFIX,178.com,DC
  - DOMAIN-SUFFIX,17k.com,DC
  - DOMAIN-SUFFIX,360doc.com,DC
  - DOMAIN-SUFFIX,36kr.com,DC
  - DOMAIN-SUFFIX,3dmgame.com,DC
  - DOMAIN-SUFFIX,51cto.com,DC
  - DOMAIN-SUFFIX,51job.com,DC
  - DOMAIN-SUFFIX,51jobcdn.com,DC
  - DOMAIN-SUFFIX,56.com,DC
  - DOMAIN-SUFFIX,8686c.com,DC
  - DOMAIN-SUFFIX,abchina.com,DC
  - DOMAIN-SUFFIX,abercrombie.com,DC
  - DOMAIN-SUFFIX,acfun.tv,DC
  - DOMAIN-SUFFIX,air-matters.com,DC
  - DOMAIN-SUFFIX,air-matters.io,DC
  - DOMAIN-SUFFIX,aixifan.com,DC
  - DOMAIN-SUFFIX,algocasts.io,DC
  - DOMAIN-SUFFIX,babytree.com,DC
  - DOMAIN-SUFFIX,babytreeimg.com,DC
  - DOMAIN-SUFFIX,baicizhan.com,DC
  - DOMAIN-SUFFIX,baidupan.com,DC
  - DOMAIN-SUFFIX,baike.com,DC
  - DOMAIN-SUFFIX,biqudu.com,DC
  - DOMAIN-SUFFIX,biquge.com,DC
  - DOMAIN-SUFFIX,bitauto.com,DC
  - DOMAIN-SUFFIX,bosszhipin.com,DC
  - DOMAIN-SUFFIX,c-ctrip.com,DC
  - DOMAIN-SUFFIX,camera360.com,DC
  - DOMAIN-SUFFIX,cdnmama.com,DC
  - DOMAIN-SUFFIX,chaoxing.com,DC
  - DOMAIN-SUFFIX,che168.com,DC
  - DOMAIN-SUFFIX,chinacache.net,DC
  - DOMAIN-SUFFIX,chinaso.com,DC
  - DOMAIN-SUFFIX,chinaz.com,DC
  - DOMAIN-SUFFIX,chinaz.net,DC
  - DOMAIN-SUFFIX,chuimg.com,DC
  - DOMAIN-SUFFIX,cibntv.net,DC
  - DOMAIN-SUFFIX,clouddn.com,DC
  - DOMAIN-SUFFIX,cloudxns.net,DC
  - DOMAIN-SUFFIX,cn163.net,DC
  - DOMAIN-SUFFIX,cnblogs.com,DC
  - DOMAIN-SUFFIX,cnki.net,DC
  - DOMAIN-SUFFIX,cnmstl.net,DC
  - DOMAIN-SUFFIX,coolapk.com,DC
  - DOMAIN-SUFFIX,coolapkmarket.com,DC
  - DOMAIN-SUFFIX,csdn.net,DC
  - DOMAIN-SUFFIX,ctrip.com,DC
  - DOMAIN-SUFFIX,dangdang.com,DC
  - DOMAIN-SUFFIX,dfcfw.com,DC
  - DOMAIN-SUFFIX,dianping.com,DC
  - DOMAIN-SUFFIX,dilidili.wang,DC
  - DOMAIN-SUFFIX,douban.com,DC
  - DOMAIN-SUFFIX,doubanio.com,DC
  - DOMAIN-SUFFIX,dpfile.com,DC
  - DOMAIN-SUFFIX,duowan.com,DC
  - DOMAIN-SUFFIX,dxycdn.com,DC
  - DOMAIN-SUFFIX,dytt8.net,DC
  - DOMAIN-SUFFIX,easou.com,DC
  - DOMAIN-SUFFIX,eastday.com,DC
  - DOMAIN-SUFFIX,eastmoney.com,DC
  - DOMAIN-SUFFIX,ecitic.com,DC
  - DOMAIN-SUFFIX,element-plus.org,DC
  - DOMAIN-SUFFIX,ewqcxz.com,DC
  - DOMAIN-SUFFIX,fang.com,DC
  - DOMAIN-SUFFIX,fantasy.tv,DC
  - DOMAIN-SUFFIX,feng.com,DC
  - DOMAIN-SUFFIX,fengkongcloud.com,DC
  - DOMAIN-SUFFIX,fir.im,DC
  - DOMAIN-SUFFIX,frdic.com,DC
  - DOMAIN-SUFFIX,fresh-ideas.cc,DC
  - DOMAIN-SUFFIX,ganji.com,DC
  - DOMAIN-SUFFIX,ganjistatic1.com,DC
  - DOMAIN-SUFFIX,geetest.com,DC
  - DOMAIN-SUFFIX,geilicdn.com,DC
  - DOMAIN-SUFFIX,ghpym.com,DC
  - DOMAIN-SUFFIX,godic.net,DC
  - DOMAIN-SUFFIX,guazi.com,DC
  - DOMAIN-SUFFIX,gwdang.com,DC
  - DOMAIN-SUFFIX,gzlzfm.com,DC
  - DOMAIN-SUFFIX,haibian.com,DC
  - DOMAIN-SUFFIX,haosou.com,DC
  - DOMAIN-SUFFIX,hollisterco.com,DC
  - DOMAIN-SUFFIX,hongxiu.com,DC
  - DOMAIN-SUFFIX,huajiao.com,DC
  - DOMAIN-SUFFIX,hupu.com,DC
  - DOMAIN-SUFFIX,huxiucdn.com,DC
  - DOMAIN-SUFFIX,huya.com,DC
  - DOMAIN-SUFFIX,ifeng.com,DC
  - DOMAIN-SUFFIX,ifengimg.com,DC
  - DOMAIN-SUFFIX,images-amazon.com,DC
  - DOMAIN-SUFFIX,infzm.com,DC
  - DOMAIN-SUFFIX,ipip.net,DC
  - DOMAIN-SUFFIX,it168.com,DC
  - DOMAIN-SUFFIX,ithome.com,DC
  - DOMAIN-SUFFIX,ixdzs.com,DC
  - DOMAIN-SUFFIX,jianguoyun.com,DC
  - DOMAIN-SUFFIX,jianshu.com,DC
  - DOMAIN-SUFFIX,jianshu.io,DC
  - DOMAIN-SUFFIX,jianshuapi.com,DC
  - DOMAIN-SUFFIX,jiathis.com,DC
  - DOMAIN-SUFFIX,jmstatic.com,DC
  - DOMAIN-SUFFIX,jumei.com,DC
  - DOMAIN-SUFFIX,kaola.com,DC
  - DOMAIN-SUFFIX,knewone.com,DC
  - DOMAIN-SUFFIX,koowo.com,DC
  - DOMAIN-SUFFIX,koyso.com,DC
  - DOMAIN-SUFFIX,ksyungslb.com,DC
  - DOMAIN-SUFFIX,kuaidi100.com,DC
  - DOMAIN-SUFFIX,kugou.com,DC
  - DOMAIN-SUFFIX,lancdns.com,DC
  - DOMAIN-SUFFIX,landiannews.com,DC
  - DOMAIN-SUFFIX,lanzou.com,DC
  - DOMAIN-SUFFIX,lanzoui.com,DC
  - DOMAIN-SUFFIX,lanzoux.com,DC
  - DOMAIN-SUFFIX,lemicp.com,DC
  - DOMAIN-SUFFIX,letitfly.me,DC
  - DOMAIN-SUFFIX,lizhi.fm,DC
  - DOMAIN-SUFFIX,lizhi.io,DC
  - DOMAIN-SUFFIX,lizhifm.com,DC
  - DOMAIN-SUFFIX,luoo.net,DC
  - DOMAIN-SUFFIX,lvmama.com,DC
  - DOMAIN-SUFFIX,lxdns.com,DC
  - DOMAIN-SUFFIX,maoyan.com,DC
  - DOMAIN-SUFFIX,meilishuo.com,DC
  - DOMAIN-SUFFIX,meituan.com,DC
  - DOMAIN-SUFFIX,meituan.net,DC
  - DOMAIN-SUFFIX,meizu.com,DC
  - DOMAIN-SUFFIX,migucloud.com,DC
  - DOMAIN-SUFFIX,miguvideo.com,DC
  - DOMAIN-SUFFIX,mobike.com,DC
  - DOMAIN-SUFFIX,mogu.com,DC
  - DOMAIN-SUFFIX,mogucdn.com,DC
  - DOMAIN-SUFFIX,mogujie.com,DC
  - DOMAIN-SUFFIX,moji.com,DC
  - DOMAIN-SUFFIX,moke.com,DC
  - DOMAIN-SUFFIX,msstatic.com,DC
  - DOMAIN-SUFFIX,mubu.com,DC
  - DOMAIN-SUFFIX,myunlu.com,DC
  - DOMAIN-SUFFIX,nruan.com,DC
  - DOMAIN-SUFFIX,nuomi.com,DC
  - DOMAIN-SUFFIX,onedns.net,DC
  - DOMAIN-SUFFIX,oneplus.com,DC
  - DOMAIN-SUFFIX,onlinedown.net,DC
  - DOMAIN-SUFFIX,oracle.com,DC
  - DOMAIN-SUFFIX,oschina.net,DC
  - DOMAIN-SUFFIX,ourdvs.com,DC
  - DOMAIN-SUFFIX,polyv.net,DC
  - DOMAIN-SUFFIX,qbox.me,DC
  - DOMAIN-SUFFIX,qcloud.com,DC
  - DOMAIN-SUFFIX,qcloudcdn.com,DC
  - DOMAIN-SUFFIX,qdaily.com,DC
  - DOMAIN-SUFFIX,qdmm.com,DC
  - DOMAIN-SUFFIX,qhimg.com,DC
  - DOMAIN-SUFFIX,qianqian.com,DC
  - DOMAIN-SUFFIX,qidian.com,DC
  - DOMAIN-SUFFIX,qihucdn.com,DC
  - DOMAIN-SUFFIX,qin.io,DC
  - DOMAIN-SUFFIX,qiniu.com,DC
  - DOMAIN-SUFFIX,qiniucdn.com,DC
  - DOMAIN-SUFFIX,qiniudn.com,DC
  - DOMAIN-SUFFIX,qiushibaike.com,DC
  - DOMAIN-SUFFIX,quanmin.tv,DC
  - DOMAIN-SUFFIX,qunar.com,DC
  - DOMAIN-SUFFIX,qunarzz.com,DC
  - DOMAIN-SUFFIX,realme.com,DC
  - DOMAIN-SUFFIX,repaik.com,DC
  - DOMAIN-SUFFIX,ruguoapp.com,DC
  - DOMAIN-SUFFIX,runoob.com,DC
  - DOMAIN-SUFFIX,sankuai.com,DC
  - DOMAIN-SUFFIX,segmentfault.com,DC
  - DOMAIN-SUFFIX,sf-express.com,DC
  - DOMAIN-SUFFIX,shumilou.net,DC
  - DOMAIN-SUFFIX,simplecd.me,DC
  - DOMAIN-SUFFIX,smzdm.com,DC
  - DOMAIN-SUFFIX,snwx.com,DC
  - DOMAIN-SUFFIX,soufunimg.com,DC
  - DOMAIN-SUFFIX,sspai.com,DC
  - DOMAIN-SUFFIX,startssl.com,DC
  - DOMAIN-SUFFIX,suning.com,DC
  - DOMAIN-SUFFIX,synology.com,DC
  - DOMAIN-SUFFIX,taihe.com,DC
  - DOMAIN-SUFFIX,th-sjy.com,DC
  - DOMAIN-SUFFIX,tianqi.com,DC
  - DOMAIN-SUFFIX,tianqistatic.com,DC
  - DOMAIN-SUFFIX,tianyancha.com,DC
  - DOMAIN-SUFFIX,tianyaui.com,DC
  - DOMAIN-SUFFIX,tietuku.com,DC
  - DOMAIN-SUFFIX,tiexue.net,DC
  - DOMAIN-SUFFIX,tmiaoo.com,DC
  - DOMAIN-SUFFIX,trip.com,DC
  - DOMAIN-SUFFIX,ttmeiju.com,DC
  - DOMAIN-SUFFIX,tudou.com,DC
  - DOMAIN-SUFFIX,tuniu.com,DC
  - DOMAIN-SUFFIX,tuniucdn.com,DC
  - DOMAIN-SUFFIX,umengcloud.com,DC
  - DOMAIN-SUFFIX,upyun.com,DC
  - DOMAIN-SUFFIX,uxengine.net,DC
  - DOMAIN-SUFFIX,videocc.net,DC
  - DOMAIN-SUFFIX,vivo.com,DC
  - DOMAIN-SUFFIX,wandoujia.com,DC
  - DOMAIN-SUFFIX,weather.com,DC
  - DOMAIN-SUFFIX,weico.cc,DC
  - DOMAIN-SUFFIX,weidian.com,DC
  - DOMAIN-SUFFIX,weiphone.com,DC
  - DOMAIN-SUFFIX,weiphone.net,DC
  - DOMAIN-SUFFIX,womai.com,DC
  - DOMAIN-SUFFIX,wscdns.com,DC
  - DOMAIN-SUFFIX,xdrig.com,DC
  - DOMAIN-SUFFIX,xhscdn.com,DC
  - DOMAIN-SUFFIX,xiachufang.com,DC
  - DOMAIN-SUFFIX,xiaohongshu.com,DC
  - DOMAIN-SUFFIX,xiaojukeji.com,DC
  - DOMAIN-SUFFIX,xinhuanet.com,DC
  - DOMAIN-SUFFIX,xip.io,DC
  - DOMAIN-SUFFIX,xitek.com,DC
  - DOMAIN-SUFFIX,xiumi.us,DC
  - DOMAIN-SUFFIX,xslb.net,DC
  - DOMAIN-SUFFIX,xueqiu.com,DC
  - DOMAIN-SUFFIX,yach.me,DC
  - DOMAIN-SUFFIX,yeepay.com,DC
  - DOMAIN-SUFFIX,yhd.com,DC
  - DOMAIN-SUFFIX,yihaodianimg.com,DC
  - DOMAIN-SUFFIX,yinxiang.com,DC
  - DOMAIN-SUFFIX,yinyuetai.com,DC
  - DOMAIN-SUFFIX,yixia.com,DC
  - DOMAIN-SUFFIX,ys168.com,DC
  - DOMAIN-SUFFIX,yuewen.com,DC
  - DOMAIN-SUFFIX,yy.com,DC
  - DOMAIN-SUFFIX,yystatic.com,DC
  - DOMAIN-SUFFIX,zealer.com,DC
  - DOMAIN-SUFFIX,zhangzishi.cc,DC
  - DOMAIN-SUFFIX,zhanqi.tv,DC
  - DOMAIN-SUFFIX,zhaopin.com,DC
  - DOMAIN-SUFFIX,zhihu.com,DC
  - DOMAIN-SUFFIX,zhimg.com,DC
  - DOMAIN-SUFFIX,zhipin.com,DC
  - DOMAIN-SUFFIX,zhongsou.com,DC
  - DOMAIN-SUFFIX,zhuihd.com,DC
  - IP-CIDR,8.128.0.0/10,DC,no-resolve
  - IP-CIDR,8.208.0.0/12,DC,no-resolve
  - IP-CIDR,14.1.112.0/22,DC,no-resolve
  - IP-CIDR,41.222.240.0/22,DC,no-resolve
  - IP-CIDR,41.223.119.0/24,DC,no-resolve
  - IP-CIDR,43.242.168.0/22,DC,no-resolve
  - IP-CIDR,45.112.212.0/22,DC,no-resolve
  - IP-CIDR,47.52.0.0/16,DC,no-resolve
  - IP-CIDR,47.56.0.0/15,DC,no-resolve
  - IP-CIDR,47.74.0.0/15,DC,no-resolve
  - IP-CIDR,47.76.0.0/14,DC,no-resolve
  - IP-CIDR,47.80.0.0/12,DC,no-resolve
  - IP-CIDR,47.235.0.0/16,DC,no-resolve
  - IP-CIDR,47.236.0.0/14,DC,no-resolve
  - IP-CIDR,47.240.0.0/14,DC,no-resolve
  - IP-CIDR,47.244.0.0/15,DC,no-resolve
  - IP-CIDR,47.246.0.0/16,DC,no-resolve
  - IP-CIDR,47.250.0.0/15,DC,no-resolve
  - IP-CIDR,47.252.0.0/15,DC,no-resolve
  - IP-CIDR,47.254.0.0/16,DC,no-resolve
  - IP-CIDR,59.82.0.0/20,DC,no-resolve
  - IP-CIDR,59.82.240.0/21,DC,no-resolve
  - IP-CIDR,59.82.248.0/22,DC,no-resolve
  - IP-CIDR,72.254.0.0/16,DC,no-resolve
  - IP-CIDR,103.38.56.0/22,DC,no-resolve
  - IP-CIDR,103.52.76.0/22,DC,no-resolve
  - IP-CIDR,103.206.40.0/22,DC,no-resolve
  - IP-CIDR,110.76.21.0/24,DC,no-resolve
  - IP-CIDR,110.76.23.0/24,DC,no-resolve
  - IP-CIDR,112.125.0.0/17,DC,no-resolve
  - IP-CIDR,116.251.64.0/18,DC,no-resolve
  - IP-CIDR,119.38.208.0/20,DC,no-resolve
  - IP-CIDR,119.38.224.0/20,DC,no-resolve
  - IP-CIDR,119.42.224.0/20,DC,no-resolve
  - IP-CIDR,139.95.0.0/16,DC,no-resolve
  - IP-CIDR,140.205.1.0/24,DC,no-resolve
  - IP-CIDR,140.205.122.0/24,DC,no-resolve
  - IP-CIDR,147.139.0.0/16,DC,no-resolve
  - IP-CIDR,149.129.0.0/16,DC,no-resolve
  - IP-CIDR,155.102.0.0/16,DC,no-resolve
  - IP-CIDR,161.117.0.0/16,DC,no-resolve
  - IP-CIDR,163.181.0.0/16,DC,no-resolve
  - IP-CIDR,170.33.0.0/16,DC,no-resolve
  - IP-CIDR,198.11.128.0/18,DC,no-resolve
  - IP-CIDR,205.204.96.0/19,DC,no-resolve
  - IP-CIDR,19.28.0.0/23,DC,no-resolve
  - IP-CIDR,45.40.192.0/19,DC,no-resolve
  - IP-CIDR,49.51.0.0/16,DC,no-resolve
  - IP-CIDR,62.234.0.0/16,DC,no-resolve
  - IP-CIDR,94.191.0.0/17,DC,no-resolve
  - IP-CIDR,103.7.28.0/22,DC,no-resolve
  - IP-CIDR,103.116.50.0/23,DC,no-resolve
  - IP-CIDR,103.231.60.0/24,DC,no-resolve
  - IP-CIDR,109.244.0.0/16,DC,no-resolve
  - IP-CIDR,111.30.128.0/21,DC,no-resolve
  - IP-CIDR,111.30.136.0/24,DC,no-resolve
  - IP-CIDR,111.30.139.0/24,DC,no-resolve
  - IP-CIDR,111.30.140.0/23,DC,no-resolve
  - IP-CIDR,115.159.0.0/16,DC,no-resolve
  - IP-CIDR,119.28.0.0/15,DC,no-resolve
  - IP-CIDR,120.88.56.0/23,DC,no-resolve
  - IP-CIDR,121.51.0.0/16,DC,no-resolve
  - IP-CIDR,129.28.0.0/16,DC,no-resolve
  - IP-CIDR,129.204.0.0/16,DC,no-resolve
  - IP-CIDR,129.211.0.0/16,DC,no-resolve
  - IP-CIDR,132.232.0.0/16,DC,no-resolve
  - IP-CIDR,134.175.0.0/16,DC,no-resolve
  - IP-CIDR,146.56.192.0/18,DC,no-resolve
  - IP-CIDR,148.70.0.0/16,DC,no-resolve
  - IP-CIDR,150.109.0.0/16,DC,no-resolve
  - IP-CIDR,152.136.0.0/16,DC,no-resolve
  - IP-CIDR,162.14.0.0/16,DC,no-resolve
  - IP-CIDR,162.62.0.0/16,DC,no-resolve
  - IP-CIDR,170.106.130.0/24,DC,no-resolve
  - IP-CIDR,182.254.0.0/16,DC,no-resolve
  - IP-CIDR,188.131.128.0/17,DC,no-resolve
  - IP-CIDR,203.195.128.0/17,DC,no-resolve
  - IP-CIDR,203.205.128.0/17,DC,no-resolve
  - IP-CIDR,210.4.138.0/24,DC,no-resolve
  - IP-CIDR,211.152.128.0/23,DC,no-resolve
  - IP-CIDR,211.152.132.0/23,DC,no-resolve
  - IP-CIDR,211.152.148.0/23,DC,no-resolve
  - IP-CIDR,212.64.0.0/17,DC,no-resolve
  - IP-CIDR,212.129.128.0/17,DC,no-resolve
  - IP-CIDR,45.113.192.0/22,DC,no-resolve
  - IP-CIDR,63.217.23.0/24,DC,no-resolve
  - IP-CIDR,63.243.252.0/24,DC,no-resolve
  - IP-CIDR,103.235.44.0/22,DC,no-resolve
  - IP-CIDR,104.193.88.0/22,DC,no-resolve
  - IP-CIDR,106.12.0.0/15,DC,no-resolve
  - IP-CIDR,114.28.224.0/20,DC,no-resolve
  - IP-CIDR,119.63.192.0/21,DC,no-resolve
  - IP-CIDR,180.76.0.0/24,DC,no-resolve
  - IP-CIDR,180.76.0.0/16,DC,no-resolve
  - IP-CIDR,182.61.0.0/16,DC,no-resolve
  - IP-CIDR,185.10.104.0/22,DC,no-resolve
  - IP-CIDR,202.46.48.0/20,DC,no-resolve
  - IP-CIDR,203.90.238.0/24,DC,no-resolve
  - IP-CIDR,43.254.0.0/22,DC,no-resolve
  - IP-CIDR,45.249.212.0/22,DC,no-resolve
  - IP-CIDR,49.4.0.0/17,DC,no-resolve
  - IP-CIDR,78.101.192.0/19,DC,no-resolve
  - IP-CIDR,78.101.224.0/20,DC,no-resolve
  - IP-CIDR,81.52.161.0/24,DC,no-resolve
  - IP-CIDR,85.97.220.0/22,DC,no-resolve
  - IP-CIDR,103.31.200.0/22,DC,no-resolve
  - IP-CIDR,103.69.140.0/23,DC,no-resolve
  - IP-CIDR,103.218.216.0/22,DC,no-resolve
  - IP-CIDR,114.115.128.0/17,DC,no-resolve
  - IP-CIDR,114.116.0.0/16,DC,no-resolve
  - IP-CIDR,116.63.128.0/18,DC,no-resolve
  - IP-CIDR,116.66.184.0/22,DC,no-resolve
  - IP-CIDR,116.71.96.0/20,DC,no-resolve
  - IP-CIDR,116.71.128.0/21,DC,no-resolve
  - IP-CIDR,116.71.136.0/22,DC,no-resolve
  - IP-CIDR,116.71.141.0/24,DC,no-resolve
  - IP-CIDR,116.71.142.0/24,DC,no-resolve
  - IP-CIDR,116.71.243.0/24,DC,no-resolve
  - IP-CIDR,116.71.244.0/24,DC,no-resolve
  - IP-CIDR,116.71.251.0/24,DC,no-resolve
  - IP-CIDR,117.78.0.0/18,DC,no-resolve
  - IP-CIDR,119.3.0.0/16,DC,no-resolve
  - IP-CIDR,119.8.0.0/21,DC,no-resolve
  - IP-CIDR,119.8.32.0/19,DC,no-resolve
  - IP-CIDR,121.36.0.0/17,DC,no-resolve
  - IP-CIDR,121.36.128.0/18,DC,no-resolve
  - IP-CIDR,121.37.0.0/17,DC,no-resolve
  - IP-CIDR,122.112.128.0/17,DC,no-resolve
  - IP-CIDR,139.9.0.0/18,DC,no-resolve
  - IP-CIDR,139.9.64.0/19,DC,no-resolve
  - IP-CIDR,139.9.100.0/22,DC,no-resolve
  - IP-CIDR,139.9.104.0/21,DC,no-resolve
  - IP-CIDR,139.9.112.0/20,DC,no-resolve
  - IP-CIDR,139.9.128.0/18,DC,no-resolve
  - IP-CIDR,139.9.192.0/19,DC,no-resolve
  - IP-CIDR,139.9.224.0/20,DC,no-resolve
  - IP-CIDR,139.9.240.0/21,DC,no-resolve
  - IP-CIDR,139.9.248.0/22,DC,no-resolve
  - IP-CIDR,139.159.128.0/19,DC,no-resolve
  - IP-CIDR,139.159.160.0/22,DC,no-resolve
  - IP-CIDR,139.159.164.0/23,DC,no-resolve
  - IP-CIDR,139.159.168.0/21,DC,no-resolve
  - IP-CIDR,139.159.176.0/20,DC,no-resolve
  - IP-CIDR,139.159.192.0/18,DC,no-resolve
  - IP-CIDR,159.138.0.0/18,DC,no-resolve
  - IP-CIDR,159.138.64.0/21,DC,no-resolve
  - IP-CIDR,159.138.79.0/24,DC,no-resolve
  - IP-CIDR,159.138.80.0/20,DC,no-resolve
  - IP-CIDR,159.138.96.0/20,DC,no-resolve
  - IP-CIDR,159.138.112.0/21,DC,no-resolve
  - IP-CIDR,159.138.125.0/24,DC,no-resolve
  - IP-CIDR,159.138.128.0/18,DC,no-resolve
  - IP-CIDR,159.138.192.0/20,DC,no-resolve
  - IP-CIDR,159.138.223.0/24,DC,no-resolve
  - IP-CIDR,159.138.224.0/19,DC,no-resolve
  - IP-CIDR,168.195.92.0/22,DC,no-resolve
  - IP-CIDR,185.176.76.0/22,DC,no-resolve
  - IP-CIDR,197.199.0.0/18,DC,no-resolve
  - IP-CIDR,197.210.163.0/24,DC,no-resolve
  - IP-CIDR,197.252.1.0/24,DC,no-resolve
  - IP-CIDR,197.252.2.0/23,DC,no-resolve
  - IP-CIDR,197.252.4.0/22,DC,no-resolve
  - IP-CIDR,197.252.8.0/21,DC,no-resolve
  - IP-CIDR,200.32.52.0/24,DC,no-resolve
  - IP-CIDR,200.32.54.0/24,DC,no-resolve
  - IP-CIDR,200.32.57.0/24,DC,no-resolve
  - IP-CIDR,203.135.0.0/22,DC,no-resolve
  - IP-CIDR,203.135.4.0/23,DC,no-resolve
  - IP-CIDR,203.135.8.0/23,DC,no-resolve
  - IP-CIDR,203.135.11.0/24,DC,no-resolve
  - IP-CIDR,203.135.13.0/24,DC,no-resolve
  - IP-CIDR,203.135.20.0/24,DC,no-resolve
  - IP-CIDR,203.135.22.0/23,DC,no-resolve
  - IP-CIDR,203.135.24.0/23,DC,no-resolve
  - IP-CIDR,203.135.26.0/24,DC,no-resolve
  - IP-CIDR,203.135.29.0/24,DC,no-resolve
  - IP-CIDR,203.135.33.0/24,DC,no-resolve
  - IP-CIDR,203.135.38.0/23,DC,no-resolve
  - IP-CIDR,203.135.40.0/24,DC,no-resolve
  - IP-CIDR,203.135.43.0/24,DC,no-resolve
  - IP-CIDR,203.135.48.0/24,DC,no-resolve
  - IP-CIDR,203.135.50.0/24,DC,no-resolve
  - IP-CIDR,42.186.0.0/16,DC,no-resolve
  - IP-CIDR,45.127.128.0/22,DC,no-resolve
  - IP-CIDR,45.195.24.0/24,DC,no-resolve
  - IP-CIDR,45.253.132.0/22,DC,no-resolve
  - IP-CIDR,45.253.240.0/22,DC,no-resolve
  - IP-CIDR,45.254.48.0/23,DC,no-resolve
  - IP-CIDR,59.111.0.0/20,DC,no-resolve
  - IP-CIDR,59.111.128.0/17,DC,no-resolve
  - IP-CIDR,103.71.120.0/21,DC,no-resolve
  - IP-CIDR,103.71.128.0/22,DC,no-resolve
  - IP-CIDR,103.71.196.0/22,DC,no-resolve
  - IP-CIDR,103.71.200.0/22,DC,no-resolve
  - IP-CIDR,103.72.12.0/22,DC,no-resolve
  - IP-CIDR,103.72.18.0/23,DC,no-resolve
  - IP-CIDR,103.72.24.0/22,DC,no-resolve
  - IP-CIDR,103.72.28.0/23,DC,no-resolve
  - IP-CIDR,103.72.38.0/23,DC,no-resolve
  - IP-CIDR,103.72.40.0/23,DC,no-resolve
  - IP-CIDR,103.72.44.0/22,DC,no-resolve
  - IP-CIDR,103.72.48.0/21,DC,no-resolve
  - IP-CIDR,103.72.128.0/21,DC,no-resolve
  - IP-CIDR,103.74.24.0/21,DC,no-resolve
  - IP-CIDR,103.74.48.0/22,DC,no-resolve
  - IP-CIDR,103.126.92.0/22,DC,no-resolve
  - IP-CIDR,103.129.252.0/22,DC,no-resolve
  - IP-CIDR,103.131.252.0/22,DC,no-resolve
  - IP-CIDR,103.135.240.0/22,DC,no-resolve
  - IP-CIDR,103.196.64.0/22,DC,no-resolve
  - IP-CIDR,106.2.32.0/19,DC,no-resolve
  - IP-CIDR,106.2.64.0/18,DC,no-resolve
  - IP-CIDR,114.113.196.0/22,DC,no-resolve
  - IP-CIDR,114.113.200.0/22,DC,no-resolve
  - IP-CIDR,115.236.112.0/20,DC,no-resolve
  - IP-CIDR,115.238.76.0/22,DC,no-resolve
  - IP-CIDR,123.58.160.0/19,DC,no-resolve
  - IP-CIDR,223.252.192.0/19,DC,no-resolve
  - IP-CIDR,101.198.128.0/18,DC,no-resolve
  - IP-CIDR,101.198.192.0/19,DC,no-resolve
  - IP-CIDR,101.199.196.0/22,DC,no-resolve
  - PROCESS-NAME,aria2c.exe,DC
  - PROCESS-NAME,fdm.exe,DC
  - PROCESS-NAME,Folx.exe,DC
  - PROCESS-NAME,NetTransport.exe,DC
  - PROCESS-NAME,Thunder.exe,DC
  - PROCESS-NAME,Transmission.exe,DC
  - PROCESS-NAME,uTorrent.exe,DC
  - PROCESS-NAME,WebTorrent.exe,DC
  - PROCESS-NAME,WebTorrent Helper.exe,DC
  - PROCESS-NAME,qbittorrent.exe,DC
  - DOMAIN-SUFFIX,smtp,DC
  - DOMAIN-KEYWORD,aria2,DC
  - PROCESS-NAME,DownloadService.exe,DC
  - PROCESS-NAME,Weiyun.exe,DC
  - PROCESS-NAME,baidunetdisk.exe,DC
  - DOMAIN,ic.adobe.io,AD-BAN
  - DOMAIN,cc-api-data.adobe.io,AD-BAN
  - DOMAIN,cc-api-data-stage.adobe.io,AD-BAN
  - DOMAIN,prod.adobegenuine.com,AD-BAN
  - DOMAIN,gocart-web-prod-ue1-alb-1461435473.us-east-1.elb.amazonaws.com,AD-BAN
  - DOMAIN,0mo5a70cqa.adobe.io,AD-BAN
  - DOMAIN,1b9khekel6.adobe.io,AD-BAN
  - DOMAIN,1hzopx6nz7.adobe.io,AD-BAN
  - DOMAIN,22gda3bxkb.adobe.io,AD-BAN
  - DOMAIN,23ynjitwt5.adobe.io,AD-BAN
  - DOMAIN,2ftem87osk.adobe.io,AD-BAN
  - DOMAIN,3ca52znvmj.adobe.io,AD-BAN
  - DOMAIN,3d3wqt96ht.adobe.io,AD-BAN
  - DOMAIN,4vzokhpsbs.adobe.io,AD-BAN
  - DOMAIN,5zgzzv92gn.adobe.io,AD-BAN
  - DOMAIN,69tu0xswvq.adobe.io,AD-BAN
  - DOMAIN,7g2gzgk9g1.adobe.io,AD-BAN
  - DOMAIN,7m31guub0q.adobe.io,AD-BAN
  - DOMAIN,7sj9n87sls.adobe.io,AD-BAN
  - DOMAIN,8ncdzpmmrg.adobe.io,AD-BAN
  - DOMAIN,9ngulmtgqi.adobe.io,AD-BAN
  - DOMAIN,aoorovjtha.adobe.io,AD-BAN
  - DOMAIN,b5kbg2ggog.adobe.io,AD-BAN
  - DOMAIN,cd536oo20y.adobe.io,AD-BAN
  - DOMAIN,dxyeyf6ecy.adobe.io,AD-BAN
  - DOMAIN,dyzt55url8.adobe.io,AD-BAN
  - DOMAIN,fgh5v09kcn.adobe.io,AD-BAN
  - DOMAIN,fqaq3pq1o9.adobe.io,AD-BAN
  - DOMAIN,guzg78logz.adobe.io,AD-BAN
  - DOMAIN,gw8gfjbs05.adobe.io,AD-BAN
  - DOMAIN,i7pq6fgbsl.adobe.io,AD-BAN
  - DOMAIN,ij0gdyrfka.adobe.io,AD-BAN
  - DOMAIN,ivbnpthtl2.adobe.io,AD-BAN
  - DOMAIN,jc95y2v12r.adobe.io,AD-BAN
  - DOMAIN,lre1kgz2u4.adobe.io,AD-BAN
  - DOMAIN,m59b4msyph.adobe.io,AD-BAN
  - DOMAIN,p0bjuoe16a.adobe.io,AD-BAN
  - DOMAIN,p7uxzbht8h.adobe.io,AD-BAN
  - DOMAIN,ph0f2h2csf.adobe.io,AD-BAN
  - DOMAIN,pojvrj7ho5.adobe.io,AD-BAN
  - DOMAIN,r3zj0yju1q.adobe.io,AD-BAN
  - DOMAIN,r5hacgq5w6.adobe.io,AD-BAN
  - DOMAIN,vajcbj9qgq.adobe.io,AD-BAN
  - DOMAIN,vcorzsld2a.adobe.io,AD-BAN
  - DOMAIN,7hewqka7ix.adobe.io,AD-BAN
  - DOMAIN,4hvtkfouhu.adobe.io,AD-BAN
  - DOMAIN,bo3u7sbfvf.adobe.io,AD-BAN
  - DOMAIN,h9m2j0ykj7.adobe.io,AD-BAN
  - DOMAIN,8n1u6aggep.adobe.io,AD-BAN
  - DOMAIN,ej4o5b9gac.adobe.io,AD-BAN
  - DOMAIN,hu0em4wmio.adobe.io,AD-BAN
  - DOMAIN,q2ge7bxibl.adobe.io,AD-BAN
  - DOMAIN,zh9yrmh2lu.adobe.io,AD-BAN
  - DOMAIN,cv218qmzox6.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv24b15c1z0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv24v41zibm.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv256ds6c99.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2b0yc07ls.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2bqhsp36w.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2fcqvzl1r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2l4573ukh.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2nn9r0j2r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2ska86hnt.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2ys4tjt9x.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2yt8sqmh0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,cv2zp87w2eo.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv218qmzox6.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv24b15c1z0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv24v41zibm.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv256ds6c99.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2b0yc07ls.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2bqhsp36w.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2fcqvzl1r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2l4573ukh.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2nn9r0j2r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2ska86hnt.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2ys4tjt9x.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2yt8sqmh0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,iv2zp87w2eo.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv218qmzox6.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv24b15c1z0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv24v41zibm.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv256ds6c99.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2b0yc07ls.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2bqhsp36w.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2fcqvzl1r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2l4573ukh.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2nn9r0j2r.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2ska86hnt.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2ys4tjt9x.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2yt8sqmh0.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,pv2zp87w2eo.prod.cloud.adobe.io,AD-BAN
  - DOMAIN,0bj2epfqn1.adobestats.io,AD-BAN
  - DOMAIN,0n8wirm0nv.adobestats.io,AD-BAN
  - DOMAIN,124hzdrtoi.adobestats.io,AD-BAN
  - DOMAIN,17ov1u3gio.adobestats.io,AD-BAN
  - DOMAIN,17vpu0xkm6.adobestats.io,AD-BAN
  - DOMAIN,1ei1f4k9yk.adobestats.io,AD-BAN
  - DOMAIN,1ngcws40i2.adobestats.io,AD-BAN
  - DOMAIN,1qwiekvkux.adobestats.io,AD-BAN
  - DOMAIN,1tw2l9x7xb.adobestats.io,AD-BAN
  - DOMAIN,1unk1rv07w.adobestats.io,AD-BAN
  - DOMAIN,1xuyy0mk2p.adobestats.io,AD-BAN
  - DOMAIN,220zxtbjjl.adobestats.io,AD-BAN
  - DOMAIN,2621x1nzeq.adobestats.io,AD-BAN
  - DOMAIN,28t4psttw7.adobestats.io,AD-BAN
  - DOMAIN,2dhh9vsp39.adobestats.io,AD-BAN
  - DOMAIN,2eiuxr4ky7.adobestats.io,AD-BAN
  - DOMAIN,2o3c6rbyfr.adobestats.io,AD-BAN
  - DOMAIN,2qj10f8rdg.adobestats.io,AD-BAN
  - DOMAIN,2qjz50z5lf.adobestats.io,AD-BAN
  - DOMAIN,31q40256l4.adobestats.io,AD-BAN
  - DOMAIN,34modi5s5d.adobestats.io,AD-BAN
  - DOMAIN,34u96h6rvn.adobestats.io,AD-BAN
  - DOMAIN,3aqshzqv3w.adobestats.io,AD-BAN
  - DOMAIN,3jq65qgxeh.adobestats.io,AD-BAN
  - DOMAIN,3odrrlydxt.adobestats.io,AD-BAN
  - DOMAIN,3u6k9as4bj.adobestats.io,AD-BAN
  - DOMAIN,3uyby7kphu.adobestats.io,AD-BAN
  - DOMAIN,3xuuprv9lg.adobestats.io,AD-BAN
  - DOMAIN,41yq116gxd.adobestats.io,AD-BAN
  - DOMAIN,44qnmxgtif.adobestats.io,AD-BAN
  - DOMAIN,4dviy9tb3o.adobestats.io,AD-BAN
  - DOMAIN,4fmzz4au8r.adobestats.io,AD-BAN
  - DOMAIN,4l6gggpz15.adobestats.io,AD-BAN
  - DOMAIN,4yw5exucf6.adobestats.io,AD-BAN
  - DOMAIN,50sxgwgngu.adobestats.io,AD-BAN
  - DOMAIN,54cu4v5twu.adobestats.io,AD-BAN
  - DOMAIN,561r5c3bz1.adobestats.io,AD-BAN
  - DOMAIN,5ky0dijg73.adobestats.io,AD-BAN
  - DOMAIN,5m62o8ud26.adobestats.io,AD-BAN
  - DOMAIN,5pawwgngcc.adobestats.io,AD-BAN
  - DOMAIN,5zcrcdpvlp.adobestats.io,AD-BAN
  - DOMAIN,69rxfbohle.adobestats.io,AD-BAN
  - DOMAIN,6dnh2pnz6e.adobestats.io,AD-BAN
  - DOMAIN,6eidhihhci.adobestats.io,AD-BAN
  - DOMAIN,6j0onv1tde.adobestats.io,AD-BAN
  - DOMAIN,6mmsqon7y7.adobestats.io,AD-BAN
  - DOMAIN,6purj8tuwe.adobestats.io,AD-BAN
  - DOMAIN,6qkk0k4e9n.adobestats.io,AD-BAN
  - DOMAIN,6t38sdao5e.adobestats.io,AD-BAN
  - DOMAIN,6y6ozj4sot.adobestats.io,AD-BAN
  - DOMAIN,6zknqfiyev.adobestats.io,AD-BAN
  - DOMAIN,79j7psfqg5.adobestats.io,AD-BAN
  - DOMAIN,7k1t5im229.adobestats.io,AD-BAN
  - DOMAIN,7l4xxjhvkt.adobestats.io,AD-BAN
  - DOMAIN,7tu619a87v.adobestats.io,AD-BAN
  - DOMAIN,83x20gw5jk.adobestats.io,AD-BAN
  - DOMAIN,85n85uoa1h.adobestats.io,AD-BAN
  - DOMAIN,8tegcsplp5.adobestats.io,AD-BAN
  - DOMAIN,98c6c096dd.adobestats.io,AD-BAN
  - DOMAIN,98yu7gk4m3.adobestats.io,AD-BAN
  - DOMAIN,99pfl4vazm.adobestats.io,AD-BAN
  - DOMAIN,9g12qgnfe4.adobestats.io,AD-BAN
  - DOMAIN,9iay914wzy.adobestats.io,AD-BAN
  - DOMAIN,9orhsmzhzs.adobestats.io,AD-BAN
  - DOMAIN,9uffo0j6wj.adobestats.io,AD-BAN
  - DOMAIN,9wm8di7ifk.adobestats.io,AD-BAN
  - DOMAIN,a1y2b7wsna.adobestats.io,AD-BAN
  - DOMAIN,a3cgga0v52.adobestats.io,AD-BAN
  - DOMAIN,a9ctb1jmbv.adobestats.io,AD-BAN
  - DOMAIN,ag0ak456at.adobestats.io,AD-BAN
  - DOMAIN,agxqobl83f.adobestats.io,AD-BAN
  - DOMAIN,ah5otkl8ie.adobestats.io,AD-BAN
  - DOMAIN,altz51db7t.adobestats.io,AD-BAN
  - DOMAIN,anl33sxvkb.adobestats.io,AD-BAN
  - DOMAIN,bbraowhh29.adobestats.io,AD-BAN
  - DOMAIN,bjooauydoa.adobestats.io,AD-BAN
  - DOMAIN,bk7y1gneyk.adobestats.io,AD-BAN
  - DOMAIN,bk8pzmo8g4.adobestats.io,AD-BAN
  - DOMAIN,bpvcty7ry7.adobestats.io,AD-BAN
  - DOMAIN,bs2yhuojzm.adobestats.io,AD-BAN
  - DOMAIN,c474kdh1ky.adobestats.io,AD-BAN
  - DOMAIN,c4dpyxapo7.adobestats.io,AD-BAN
  - DOMAIN,cde0alxs25.adobestats.io,AD-BAN
  - DOMAIN,cr2fouxnpm.adobestats.io,AD-BAN
  - DOMAIN,curbpindd3.adobestats.io,AD-BAN
  - DOMAIN,d101mw99xq.adobestats.io,AD-BAN
  - DOMAIN,d2ke1291mx.adobestats.io,AD-BAN
  - DOMAIN,d6zco8is6l.adobestats.io,AD-BAN
  - DOMAIN,dfnm3epsb7.adobestats.io,AD-BAN
  - DOMAIN,dru0w44scl.adobestats.io,AD-BAN
  - DOMAIN,dsj4bsmk6i.adobestats.io,AD-BAN
  - DOMAIN,dx0nvmv4hz.adobestats.io,AD-BAN
  - DOMAIN,dymfhyu5t7.adobestats.io,AD-BAN
  - DOMAIN,dyv9axahup.adobestats.io,AD-BAN
  - DOMAIN,ebvf40engd.adobestats.io,AD-BAN
  - DOMAIN,eftcpaiu36.adobestats.io,AD-BAN
  - DOMAIN,eq7dbze88m.adobestats.io,AD-BAN
  - DOMAIN,eqo0sr8daw.adobestats.io,AD-BAN
  - DOMAIN,esx6aswt5e.adobestats.io,AD-BAN
  - DOMAIN,eu927m40hm.adobestats.io,AD-BAN
  - DOMAIN,eyiu19jd5w.adobestats.io,AD-BAN
  - DOMAIN,ffirm4ruur.adobestats.io,AD-BAN
  - DOMAIN,ffs3xik41x.adobestats.io,AD-BAN
  - DOMAIN,fm8m3wxufy.adobestats.io,AD-BAN
  - DOMAIN,fw6x2fs3fr.adobestats.io,AD-BAN
  - DOMAIN,g0rhyhkd7l.adobestats.io,AD-BAN
  - DOMAIN,g3y09mbaam.adobestats.io,AD-BAN
  - DOMAIN,g9cli80sqp.adobestats.io,AD-BAN
  - DOMAIN,gwbpood8w4.adobestats.io,AD-BAN
  - DOMAIN,hf6s5jdv95.adobestats.io,AD-BAN
  - DOMAIN,hijfpxclgz.adobestats.io,AD-BAN
  - DOMAIN,hjs70w1pdi.adobestats.io,AD-BAN
  - DOMAIN,hmonvr006v.adobestats.io,AD-BAN
  - DOMAIN,hnk7phkxtg.adobestats.io,AD-BAN
  - DOMAIN,hq0mnwz735.adobestats.io,AD-BAN
  - DOMAIN,hwfqhlenbg.adobestats.io,AD-BAN
  - DOMAIN,i2x2ius9o5.adobestats.io,AD-BAN
  - DOMAIN,i4x0voa7ns.adobestats.io,AD-BAN
  - DOMAIN,i6gl29bvy6.adobestats.io,AD-BAN
  - DOMAIN,ijl01wuoed.adobestats.io,AD-BAN
  - DOMAIN,iw4sp0v9h3.adobestats.io,AD-BAN
  - DOMAIN,izke0wrq9n.adobestats.io,AD-BAN
  - DOMAIN,j0qztjp9ep.adobestats.io,AD-BAN
  - DOMAIN,j134yk6hv5.adobestats.io,AD-BAN
  - DOMAIN,j14y4uzge7.adobestats.io,AD-BAN
  - DOMAIN,j5vsm79i8a.adobestats.io,AD-BAN
  - DOMAIN,jaircqa037.adobestats.io,AD-BAN
  - DOMAIN,jatil41mhk.adobestats.io,AD-BAN
  - DOMAIN,je5ufnklzs.adobestats.io,AD-BAN
  - DOMAIN,jfb7fqf90c.adobestats.io,AD-BAN
  - DOMAIN,jir97hss11.adobestats.io,AD-BAN
  - DOMAIN,jmx50quqz0.adobestats.io,AD-BAN
  - DOMAIN,jsspeczo2f.adobestats.io,AD-BAN
  - DOMAIN,jsxfc5yij1.adobestats.io,AD-BAN
  - DOMAIN,jwonv590qs.adobestats.io,AD-BAN
  - DOMAIN,jye4987hyr.adobestats.io,AD-BAN
  - DOMAIN,k9cyzt2wha.adobestats.io,AD-BAN
  - DOMAIN,kbdgy1yszf.adobestats.io,AD-BAN
  - DOMAIN,kgj0gsg3cf.adobestats.io,AD-BAN
  - DOMAIN,kjhzwuhcel.adobestats.io,AD-BAN
  - DOMAIN,klw4np5a1x.adobestats.io,AD-BAN
  - DOMAIN,kvi8uopy6f.adobestats.io,AD-BAN
  - DOMAIN,kvn19sesfx.adobestats.io,AD-BAN
  - DOMAIN,kwi5n2ruax.adobestats.io,AD-BAN
  - DOMAIN,l558s6jwzy.adobestats.io,AD-BAN
  - DOMAIN,ll8xjr580v.adobestats.io,AD-BAN
  - DOMAIN,llnh72p5m3.adobestats.io,AD-BAN
  - DOMAIN,lnwbupw1s7.adobestats.io,AD-BAN
  - DOMAIN,ltjlscpozx.adobestats.io,AD-BAN
  - DOMAIN,lv5yrjxh6i.adobestats.io,AD-BAN
  - DOMAIN,lz2x4rks1u.adobestats.io,AD-BAN
  - DOMAIN,m59cps6x3n.adobestats.io,AD-BAN
  - DOMAIN,m95pt874uw.adobestats.io,AD-BAN
  - DOMAIN,mge8tcrsbr.adobestats.io,AD-BAN
  - DOMAIN,mid2473ggd.adobestats.io,AD-BAN
  - DOMAIN,mme5z7vvqy.adobestats.io,AD-BAN
  - DOMAIN,mpsige2va9.adobestats.io,AD-BAN
  - DOMAIN,n0yaid7q47.adobestats.io,AD-BAN
  - DOMAIN,n17cast4au.adobestats.io,AD-BAN
  - DOMAIN,n746qg9j4i.adobestats.io,AD-BAN
  - DOMAIN,n78vmdxqwc.adobestats.io,AD-BAN
  - DOMAIN,nh8wam2qd9.adobestats.io,AD-BAN
  - DOMAIN,nhc73ypmli.adobestats.io,AD-BAN
  - DOMAIN,nhs5jfxg10.adobestats.io,AD-BAN
  - DOMAIN,no95ceu36c.adobestats.io,AD-BAN
  - DOMAIN,o1qtkpin3e.adobestats.io,AD-BAN
  - DOMAIN,oee5i55vyo.adobestats.io,AD-BAN
  - DOMAIN,oh41yzugiz.adobestats.io,AD-BAN
  - DOMAIN,ok9sn4bf8f.adobestats.io,AD-BAN
  - DOMAIN,om2h3oklke.adobestats.io,AD-BAN
  - DOMAIN,oxiz2n3i4v.adobestats.io,AD-BAN
  - DOMAIN,p3lj3o9h1s.adobestats.io,AD-BAN
  - DOMAIN,p3m760solq.adobestats.io,AD-BAN
  - DOMAIN,p50zgina3e.adobestats.io,AD-BAN
  - DOMAIN,pc6sk9bygv.adobestats.io,AD-BAN
  - DOMAIN,pdb7v5ul5q.adobestats.io,AD-BAN
  - DOMAIN,pf80yxt5md.adobestats.io,AD-BAN
  - DOMAIN,pljm140ld1.adobestats.io,AD-BAN
  - DOMAIN,ppn4fq68w7.adobestats.io,AD-BAN
  - DOMAIN,psc20x5pmv.adobestats.io,AD-BAN
  - DOMAIN,px8vklwioh.adobestats.io,AD-BAN
  - DOMAIN,q9hjwppxeq.adobestats.io,AD-BAN
  - DOMAIN,qmyqpp3xs3.adobestats.io,AD-BAN
  - DOMAIN,qn2ex1zblg.adobestats.io,AD-BAN
  - DOMAIN,qp5bivnlrp.adobestats.io,AD-BAN
  - DOMAIN,qqyyhr3eqr.adobestats.io,AD-BAN
  - DOMAIN,qttaz1hur3.adobestats.io,AD-BAN
  - DOMAIN,qxc5z5sqkv.adobestats.io,AD-BAN
  - DOMAIN,r1lqxul5sr.adobestats.io,AD-BAN
  - DOMAIN,r9r6oomgms.adobestats.io,AD-BAN
  - DOMAIN,rb0u8l34kr.adobestats.io,AD-BAN
  - DOMAIN,riiohpqnpf.adobestats.io,AD-BAN
  - DOMAIN,rj669kv2lc.adobestats.io,AD-BAN
  - DOMAIN,rlo1n6mv52.adobestats.io,AD-BAN
  - DOMAIN,rm3xrk61n1.adobestats.io,AD-BAN
  - DOMAIN,rmnia8d0tr.adobestats.io,AD-BAN
  - DOMAIN,s7odt342lo.adobestats.io,AD-BAN
  - DOMAIN,sa4visje3j.adobestats.io,AD-BAN
  - DOMAIN,sbzo5r4687.adobestats.io,AD-BAN
  - DOMAIN,sfmzkcuf2f.adobestats.io,AD-BAN
  - DOMAIN,skg7pqn0al.adobestats.io,AD-BAN
  - DOMAIN,t9phy8ywkd.adobestats.io,AD-BAN
  - DOMAIN,tcxqcguhww.adobestats.io,AD-BAN
  - DOMAIN,tf3an24xls.adobestats.io,AD-BAN
  - DOMAIN,tprqy2lgua.adobestats.io,AD-BAN
  - DOMAIN,trc2fpy0j4.adobestats.io,AD-BAN
  - DOMAIN,tyradj47rp.adobestats.io,AD-BAN
  - DOMAIN,u31z50xvp9.adobestats.io,AD-BAN
  - DOMAIN,ua0pnr1x8v.adobestats.io,AD-BAN
  - DOMAIN,uf0onoepoe.adobestats.io,AD-BAN
  - DOMAIN,ujqx8lhpz4.adobestats.io,AD-BAN
  - DOMAIN,uo6uihbs9y.adobestats.io,AD-BAN
  - DOMAIN,uqshzexj7y.adobestats.io,AD-BAN
  - DOMAIN,ura7zj55r9.adobestats.io,AD-BAN
  - DOMAIN,uroc9kxpcb.adobestats.io,AD-BAN
  - DOMAIN,uytor2bsee.adobestats.io,AD-BAN
  - DOMAIN,v5nweiv7nf.adobestats.io,AD-BAN
  - DOMAIN,vfsjlgw02v.adobestats.io,AD-BAN
  - DOMAIN,vicsj37lhf.adobestats.io,AD-BAN
  - DOMAIN,vp7ih9xoxg.adobestats.io,AD-BAN
  - DOMAIN,vqiktmz3k1.adobestats.io,AD-BAN
  - DOMAIN,vqrc5mq1tm.adobestats.io,AD-BAN
  - DOMAIN,vr1i32txj7.adobestats.io,AD-BAN
  - DOMAIN,vr25z2lfqx.adobestats.io,AD-BAN
  - DOMAIN,vrz9w7o7yv.adobestats.io,AD-BAN
  - DOMAIN,vvzbv1ba9r.adobestats.io,AD-BAN
  - DOMAIN,w8x0780324.adobestats.io,AD-BAN
  - DOMAIN,wcxqmuxd4z.adobestats.io,AD-BAN
  - DOMAIN,wjoxlf5x2z.adobestats.io,AD-BAN
  - DOMAIN,wtooadkup9.adobestats.io,AD-BAN
  - DOMAIN,wz8kjkd9gc.adobestats.io,AD-BAN
  - DOMAIN,x5cupsunjc.adobestats.io,AD-BAN
  - DOMAIN,x880ulw3h0.adobestats.io,AD-BAN
  - DOMAIN,x8kb03c0jr.adobestats.io,AD-BAN
  - DOMAIN,x8thl73e7u.adobestats.io,AD-BAN
  - DOMAIN,xbd20b9wqa.adobestats.io,AD-BAN
  - DOMAIN,xesnl0ss94.adobestats.io,AD-BAN
  - DOMAIN,xm8abqacqz.adobestats.io,AD-BAN
  - DOMAIN,xqh2khegrf.adobestats.io,AD-BAN
  - DOMAIN,y2r8jzsv4p.adobestats.io,AD-BAN
  - DOMAIN,y53h2xkr61.adobestats.io,AD-BAN
  - DOMAIN,y8f3hhzhsk.adobestats.io,AD-BAN
  - DOMAIN,yaxne83fvv.adobestats.io,AD-BAN
  - DOMAIN,yb6j6g0r1n.adobestats.io,AD-BAN
  - DOMAIN,yj8yx3y8zo.adobestats.io,AD-BAN
  - DOMAIN,yri0bsu0ak.adobestats.io,AD-BAN
  - DOMAIN,yshuhythub.adobestats.io,AD-BAN
  - DOMAIN,yuzuoqo0il.adobestats.io,AD-BAN
  - DOMAIN,z2cez9qgcl.adobestats.io,AD-BAN
  - DOMAIN,z2yohmd1jm.adobestats.io,AD-BAN
  - DOMAIN,z3shmocdp4.adobestats.io,AD-BAN
  - DOMAIN,zekdqanici.adobestats.io,AD-BAN
  - DOMAIN,zfzx6hae4g.adobestats.io,AD-BAN
  - DOMAIN,zmg3v61bbr.adobestats.io,AD-BAN
  - DOMAIN,zooyvml70k.adobestats.io,AD-BAN
  - DOMAIN,zqr7f445uc.adobestats.io,AD-BAN
  - DOMAIN,zr60t8ia88.adobestats.io,AD-BAN
  - DOMAIN,zrao5tdh1t.adobestats.io,AD-BAN
  - DOMAIN,zrbzvc9mel.adobestats.io,AD-BAN
  - DOMAIN,zu8yy3jkaz.adobestats.io,AD-BAN
  - DOMAIN,zz8r2o83on.adobestats.io,AD-BAN
  - DOMAIN,6ll72mpyxv.adobestats.io,AD-BAN
  - DOMAIN,g6elufzgx7.adobestats.io,AD-BAN
  - DOMAIN,gdtbhgs27n.adobestats.io,AD-BAN
  - DOMAIN,hciylk3wpv.adobestats.io,AD-BAN
  - DOMAIN,m8c5gtovwb.adobestats.io,AD-BAN
  - DOMAIN,411r4c18df.adobestats.io,AD-BAN
  - DOMAIN,475ao55klh.adobestats.io,AD-BAN
  - DOMAIN,c0cczlv877.adobestats.io,AD-BAN
  - DOMAIN,fsx0pbg4rz.adobestats.io,AD-BAN
  - DOMAIN,powfb7xi5v.adobestats.io,AD-BAN
  - DOMAIN,h3hqd6gjkd.adobestats.io,AD-BAN
  - DOMAIN,bvcj3prq1u.adobestats.io,AD-BAN
  - DOMAIN,0k6cw37ajl.adobestats.io,AD-BAN
  - DOMAIN,15phzfr05l.adobestats.io,AD-BAN
  - DOMAIN,2os6jhr955.adobestats.io,AD-BAN
  - DOMAIN,3rm6l6bqwd.adobestats.io,AD-BAN
  - DOMAIN,42fkk06z8c.adobestats.io,AD-BAN
  - DOMAIN,45gnbb50sn.adobestats.io,AD-BAN
  - DOMAIN,6482jlr7qo.adobestats.io,AD-BAN
  - DOMAIN,7lj6w2xxew.adobestats.io,AD-BAN
  - DOMAIN,8eptecerpq.adobestats.io,AD-BAN
  - DOMAIN,9k4qeathc0.adobestats.io,AD-BAN
  - DOMAIN,9yod0aafmi.adobestats.io,AD-BAN
  - DOMAIN,dr1wq4uepg.adobestats.io,AD-BAN
  - DOMAIN,i48z07b7gr.adobestats.io,AD-BAN
  - DOMAIN,me7z7bchov.adobestats.io,AD-BAN
  - DOMAIN,mvnfbgfx93.adobestats.io,AD-BAN
  - DOMAIN,nj9rqrql3b.adobestats.io,AD-BAN
  - DOMAIN,ns6ckzkjzg.adobestats.io,AD-BAN
  - DOMAIN,ouovuyeiee.adobestats.io,AD-BAN
  - DOMAIN,tld9di3jxu.adobestats.io,AD-BAN
  - DOMAIN,xa8g202i4u.adobestats.io,AD-BAN
  - DOMAIN,z83qksw5cq.adobestats.io,AD-BAN
  - DOMAIN,9mblf9n5zf.adobestats.io,AD-BAN
  - DOMAIN,be5d7iw6y1.adobestats.io,AD-BAN
  - DOMAIN,cxqenfk6in.adobestats.io,AD-BAN
  - DOMAIN,cim9wvs3is.adobestats.io,AD-BAN
  - DOMAIN,iqhvrdhql4.adobestats.io,AD-BAN
  - DOMAIN,ar1hqm61sk.adobestats.io,AD-BAN
  - DOMAIN,cducupwlaq.adobestats.io,AD-BAN
  - DOMAIN,sap3m7umfu.adobestats.io,AD-BAN
  - DOMAIN,ay8wypezvi.adobestats.io,AD-BAN
  - DOMAIN,1j3muid89l.adobestats.io,AD-BAN
  - DOMAIN,8167gz60t1.adobestats.io,AD-BAN
  - DOMAIN,2bns2f5eza.adobestats.io,AD-BAN
  - DOMAIN,2c3bqjchr6.adobestats.io,AD-BAN
  - DOMAIN,49vfady5kf.adobestats.io,AD-BAN
  - DOMAIN,7v0i13wiuf.adobestats.io,AD-BAN
  - DOMAIN,ak1ow4e0u3.adobestats.io,AD-BAN
  - DOMAIN,f8m1p3tltt.adobestats.io,AD-BAN
  - DOMAIN,l6uu15bwug.adobestats.io,AD-BAN
  - DOMAIN,rtfuwp21b3.adobestats.io,AD-BAN
  - DOMAIN,s8liwh6vbn.adobestats.io,AD-BAN
  - DOMAIN,ok02isdwcx.adobestats.io,AD-BAN
  - DOMAIN,c72tusw5wi.adobestats.io,AD-BAN
  - DOMAIN,dqaytc21nb.adobestats.io,AD-BAN
  - DOMAIN,gm2ai4nsfq.adobestats.io,AD-BAN
  - DOMAIN,hs6dwhuiwh.adobestats.io,AD-BAN
  - DOMAIN,kst1t43sji.adobestats.io,AD-BAN
  - DOMAIN,x12wor9jo6.adobestats.io,AD-BAN
  - DOMAIN,xgj8lmrcy6.adobestats.io,AD-BAN
  - DOMAIN,6unmig6t9w.adobestats.io,AD-BAN
  - DOMAIN,36ai1uk1z7.adobestats.io,AD-BAN
  - DOMAIN,8nft9ke95j.adobestats.io,AD-BAN
  - DOMAIN,9sg9gr4zf4.adobestats.io,AD-BAN
  - DOMAIN,tagtjqcvqg.adobestats.io,AD-BAN
  - DOMAIN,ztxgqqizv7.adobestats.io,AD-BAN
  - DOMAIN,7mw85h5tv4.adobestats.io,AD-BAN
  - DOMAIN,5amul9liob.adobestats.io,AD-BAN
  - DOMAIN,cfh5v77fsy.adobestats.io,AD-BAN
  - DOMAIN,dobw5hakm0.adobestats.io,AD-BAN
  - DOMAIN,08n59yhbxn.adobestats.io,AD-BAN
  - DOMAIN,0p73385wa6.adobestats.io,AD-BAN
  - DOMAIN,0vrs1f5fso.adobestats.io,AD-BAN
  - DOMAIN,5et944c3kg.adobestats.io,AD-BAN
  - DOMAIN,610o7ktxw7.adobestats.io,AD-BAN
  - DOMAIN,b8qwvscik0.adobestats.io,AD-BAN
  - DOMAIN,cvl65mxwmh.adobestats.io,AD-BAN
  - DOMAIN,dtt06hnkyj.adobestats.io,AD-BAN
  - DOMAIN,fg7bb8gi6d.adobestats.io,AD-BAN
  - DOMAIN,iy304996hm.adobestats.io,AD-BAN
  - DOMAIN,lp4og15wl5.adobestats.io,AD-BAN
  - DOMAIN,nxq02alk63.adobestats.io,AD-BAN
  - DOMAIN,ofgajs60g1.adobestats.io,AD-BAN
  - DOMAIN,om52ny8l9s.adobestats.io,AD-BAN
  - DOMAIN,s14z1kt85g.adobestats.io,AD-BAN
  - DOMAIN,tyqs8bsps8.adobestats.io,AD-BAN
  - DOMAIN,vvpexgmc5t.adobestats.io,AD-BAN
  - DOMAIN,w3ffpxhbn6.adobestats.io,AD-BAN
  - DOMAIN,w58drkayqf.adobestats.io,AD-BAN
  - DOMAIN,w8mvrujj91.adobestats.io,AD-BAN
  - DOMAIN,wjpmg2uott.adobestats.io,AD-BAN
  - DOMAIN,xljz63k33x.adobestats.io,AD-BAN
  - DOMAIN,7micpuqiwp.adobestats.io,AD-BAN
  - DOMAIN,2lb39igrph.adobestats.io,AD-BAN
  - DOMAIN,3zgi4mscuk.adobestats.io,AD-BAN
  - DOMAIN,elf5yl77ju.adobestats.io,AD-BAN
  - DOMAIN,ktb8rx6uhe.adobestats.io,AD-BAN
  - DOMAIN,heufuideue.adobestats.io,AD-BAN
  - DOMAIN,xq68npgl4w.adobestats.io,AD-BAN
  - DOMAIN,vnm70hlbn4.adobestats.io,AD-BAN
  - DOMAIN,p4hiwy76wl.adobestats.io,AD-BAN
  - DOMAIN,q7i4awui0j.adobestats.io,AD-BAN
  - DOMAIN,soirhk7bm2.adobestats.io,AD-BAN
  - DOMAIN,0789i4f3cq.adobestats.io,AD-BAN
  - DOMAIN,827x3zvk4q.adobestats.io,AD-BAN
  - DOMAIN,8ljcntz31v.adobestats.io,AD-BAN
  - DOMAIN,95yojg6epq.adobestats.io,AD-BAN
  - DOMAIN,9wcrtdzcti.adobestats.io,AD-BAN
  - DOMAIN,a3dxeq2iq9.adobestats.io,AD-BAN
  - DOMAIN,hrfn4gru1j.adobestats.io,AD-BAN
  - DOMAIN,kx8yghodgl.adobestats.io,AD-BAN
  - DOMAIN,olh5t1ccns.adobestats.io,AD-BAN
  - DOMAIN,svcgy434g6.adobestats.io,AD-BAN
  - DOMAIN,uwr2upexhs.adobestats.io,AD-BAN
  - DOMAIN,wk0sculz2x.adobestats.io,AD-BAN
  - DOMAIN,xbhspynj8t.adobestats.io,AD-BAN
  - DOMAIN,xod1t4qsyk.adobestats.io,AD-BAN
  - DOMAIN,iu7mq0jcce.adobestats.io,AD-BAN
  - DOMAIN,tdatxzi3t4.adobestats.io,AD-BAN
  - DOMAIN,rptowanjjh.adobestats.io,AD-BAN
  - DOMAIN,3cnu7l5q8s.adobestats.io,AD-BAN
  - DOMAIN,ow1o9yr32j.adobestats.io,AD-BAN
  - DOMAIN,bc27a8e3zw.adobestats.io,AD-BAN
  - DOMAIN,ok6tbgxfta.adobestats.io,AD-BAN
  - DOMAIN,9nqvoa544j.adobestats.io,AD-BAN
  - DOMAIN,arzggvbs37.adobestats.io,AD-BAN
  - DOMAIN,d8hof9a6gg.adobestats.io,AD-BAN
  - DOMAIN,qh0htdwe2n.adobestats.io,AD-BAN
  - DOMAIN,fu9wr8tk0u.adobestats.io,AD-BAN
  - DOMAIN,0ss1vovh4a.adobestats.io,AD-BAN
  - DOMAIN,15ousmguga.adobestats.io,AD-BAN
  - DOMAIN,3oidzvonpa.adobestats.io,AD-BAN
  - DOMAIN,5pjcqccrcu.adobestats.io,AD-BAN
  - DOMAIN,75ffpy5iio.adobestats.io,AD-BAN
  - DOMAIN,7fj42ny0sd.adobestats.io,AD-BAN
  - DOMAIN,drwizwikc0.adobestats.io,AD-BAN
  - DOMAIN,fl34tml8is.adobestats.io,AD-BAN
  - DOMAIN,kd4c3z4xbz.adobestats.io,AD-BAN
  - DOMAIN,ksw6oyvdk6.adobestats.io,AD-BAN
  - DOMAIN,l91nnnkmbi.adobestats.io,AD-BAN
  - DOMAIN,ln3pv36xx8.adobestats.io,AD-BAN
  - DOMAIN,m5cgk2pkdn.adobestats.io,AD-BAN
  - DOMAIN,nj66fd4dzr.adobestats.io,AD-BAN
  - DOMAIN,nl00xmmmn5.adobestats.io,AD-BAN
  - DOMAIN,wn9kta1iw4.adobestats.io,AD-BAN
  - DOMAIN,x3sszs7ihy.adobestats.io,AD-BAN
  - DOMAIN,nrenlhdc1t.adobestats.io,AD-BAN
  - DOMAIN,6nbt0kofc7.adobestats.io,AD-BAN
  - DOMAIN,kmqhqhs02w.adobestats.io,AD-BAN
  - DOMAIN,wdyav7y3rf.adobestats.io,AD-BAN
  - DOMAIN,3ysvacl1hb.adobestats.io,AD-BAN
  - DOMAIN,bqbvmlmtmo.adobestats.io,AD-BAN
  - DOMAIN,zn0o46rt48.adobestats.io,AD-BAN
  - DOMAIN,8mtavkaq40.adobestats.io,AD-BAN
  - DOMAIN,52h0nva0wa.adobestats.io,AD-BAN
  - DOMAIN,4t5jyh9fkk.adobestats.io,AD-BAN
  - DOMAIN,hen2jsru7c.adobestats.io,AD-BAN
  - DOMAIN,6tpqsy07cp.adobestats.io,AD-BAN
  - DOMAIN,0andkf1e8e.adobestats.io,AD-BAN
  - DOMAIN,2kc4lqhpto.adobestats.io,AD-BAN
  - DOMAIN,43q1uykg1z.adobestats.io,AD-BAN
  - DOMAIN,7zak80l8ic.adobestats.io,AD-BAN
  - DOMAIN,9dal0pbsx3.adobestats.io,AD-BAN
  - DOMAIN,9rcgbke6qx.adobestats.io,AD-BAN
  - DOMAIN,cwejcdduvp.adobestats.io,AD-BAN
  - DOMAIN,dq1gubixz7.adobestats.io,AD-BAN
  - DOMAIN,fc2k38te2m.adobestats.io,AD-BAN
  - DOMAIN,i1j2plx3mv.adobestats.io,AD-BAN
  - DOMAIN,lnosso28q5.adobestats.io,AD-BAN
  - DOMAIN,npt74s16x9.adobestats.io,AD-BAN
  - DOMAIN,o6pk3ypjcf.adobestats.io,AD-BAN
  - DOMAIN,pcmdl6zcfd.adobestats.io,AD-BAN
  - DOMAIN,q0z6ycmvhl.adobestats.io,AD-BAN
  - DOMAIN,quptxdg94y.adobestats.io,AD-BAN
  - DOMAIN,s4y2s7r9ah.adobestats.io,AD-BAN
  - DOMAIN,yajkeabyrj.adobestats.io,AD-BAN
  - DOMAIN,r9qg11e83v.adobestats.io,AD-BAN
  - DOMAIN,13hceguz11.adobestats.io,AD-BAN
  - DOMAIN,4xosvsrdto.adobestats.io,AD-BAN
  - DOMAIN,72p3yx09zx.adobestats.io,AD-BAN
  - DOMAIN,7gu7j31tn3.adobestats.io,AD-BAN
  - DOMAIN,hob0cz1xnx.adobestats.io,AD-BAN
  - DOMAIN,fp.adobestats.io,AD-BAN
  - DOMAIN,6woibl6fiu.adobestats.io,AD-BAN
  - DOMAIN,jh34ro8dm2.adobestats.io,AD-BAN
  - DOMAIN,sz2edaz2s9.adobestats.io,AD-BAN
  - DOMAIN,4s6bg7xces.adobestats.io,AD-BAN
  - DOMAIN,3d5rp7oyng.adobestats.io,AD-BAN
  - DOMAIN,5dec9025sr.adobestats.io,AD-BAN
  - DOMAIN,5muggmgxyb.adobestats.io,AD-BAN
  - DOMAIN,94enlu8vov.adobestats.io,AD-BAN
  - DOMAIN,9pa13v8uko.adobestats.io,AD-BAN
  - DOMAIN,csb8usj9o4.adobestats.io,AD-BAN
  - DOMAIN,dxegvh5wpp.adobestats.io,AD-BAN
  - DOMAIN,itiabkzm7h.adobestats.io,AD-BAN
  - DOMAIN,jsusbknzle.adobestats.io,AD-BAN
  - DOMAIN,tzbl46vv9o.adobestats.io,AD-BAN
  - DOMAIN,v5zm23ixg2.adobestats.io,AD-BAN
  - DOMAIN,w9m8uwm145.adobestats.io,AD-BAN
  - DOMAIN,zf37mp80xx.adobestats.io,AD-BAN
  - DOMAIN,gyt27lbjb3.adobestats.io,AD-BAN
  - DOMAIN,3m3e8ccqyo.adobestats.io,AD-BAN
  - DOMAIN,2sug8qxjag.adobestats.io,AD-BAN
  - DOMAIN,36ivntopuj.adobestats.io,AD-BAN
  - DOMAIN,1eqkbrjz78.adobestats.io,AD-BAN
  - DOMAIN,szvbv5h62r.adobestats.io,AD-BAN
  - DOMAIN,zf1aegmmle.adobestats.io,AD-BAN
  - DOMAIN,50lifxkein.adobestats.io,AD-BAN
  - DOMAIN,dfwv44wffr.adobestats.io,AD-BAN
  - DOMAIN,qwzzhqpliv.adobestats.io,AD-BAN
  - DOMAIN,0wcraxg290.adobestats.io,AD-BAN
  - DOMAIN,gpd3r2mkgs.adobestats.io,AD-BAN
  - DOMAIN,116n6tkxyr.adobestats.io,AD-BAN
  - DOMAIN,3nkkaf8h85.adobestats.io,AD-BAN
  - DOMAIN,55oguiniw8.adobestats.io,AD-BAN
  - DOMAIN,e1tyeiimw3.adobestats.io,AD-BAN
  - DOMAIN,g7zh7zqzqx.adobestats.io,AD-BAN
  - DOMAIN,gglnjgxaia.adobestats.io,AD-BAN
  - DOMAIN,h33a7kps0t.adobestats.io,AD-BAN
  - DOMAIN,jewn0nrrp8.adobestats.io,AD-BAN
  - DOMAIN,r7sawld5l6.adobestats.io,AD-BAN
  - DOMAIN,vodh16neme.adobestats.io,AD-BAN
  - DOMAIN,wntfgdo4ki.adobestats.io,AD-BAN
  - DOMAIN,x9u2jsesk0.adobestats.io,AD-BAN
  - DOMAIN,xsn76p7ntx.adobestats.io,AD-BAN
  - DOMAIN,xz9xjlyw58.adobestats.io,AD-BAN
  - DOMAIN,as73qhl83n.adobestats.io,AD-BAN
  - DOMAIN,b0giyj3mc1.adobestats.io,AD-BAN
  - DOMAIN,f9554salkg.adobestats.io,AD-BAN
  - DOMAIN,i487nlno13.adobestats.io,AD-BAN
  - DOMAIN,qx2t3lrpmg.adobestats.io,AD-BAN
  - DOMAIN,r0exxqftud.adobestats.io,AD-BAN
  - DOMAIN,spbuswk2di.adobestats.io,AD-BAN
  - DOMAIN,swxs9c0fpt.adobestats.io,AD-BAN
  - DOMAIN,v7esmx1n0s.adobestats.io,AD-BAN
  - DOMAIN,zglaizubbj.adobestats.io,AD-BAN
  - DOMAIN,22wqqv6b23.adobestats.io,AD-BAN
  - DOMAIN,5jdb1nfklf.adobestats.io,AD-BAN
  - DOMAIN,6glym36rbb.adobestats.io,AD-BAN
  - DOMAIN,6h8391pvf8.adobestats.io,AD-BAN
  - DOMAIN,c675s4pigj.adobestats.io,AD-BAN
  - DOMAIN,c8pyxo4r20.adobestats.io,AD-BAN
  - DOMAIN,co9sg87h3h.adobestats.io,AD-BAN
  - DOMAIN,f8wflegco1.adobestats.io,AD-BAN
  - DOMAIN,g6ld7orx5r.adobestats.io,AD-BAN
  - DOMAIN,r00r33ldza.adobestats.io,AD-BAN
  - DOMAIN,scmnpedxm0.adobestats.io,AD-BAN
  - DOMAIN,slx5l73jwh.adobestats.io,AD-BAN
  - DOMAIN,w8yfgti2yd.adobestats.io,AD-BAN
  - DOMAIN,yljkdk5tky.adobestats.io,AD-BAN
  - DOMAIN,0oydr1f856.adobestats.io,AD-BAN
  - DOMAIN,3ea8nnv3fo.adobestats.io,AD-BAN
  - DOMAIN,4j225l63ny.adobestats.io,AD-BAN
  - DOMAIN,4pbmn87uov.adobestats.io,AD-BAN
  - DOMAIN,8z20kcq3af.adobestats.io,AD-BAN
  - DOMAIN,bp5qqybokw.adobestats.io,AD-BAN
  - DOMAIN,dri0xipdj1.adobestats.io,AD-BAN
  - DOMAIN,e8yny99m61.adobestats.io,AD-BAN
  - DOMAIN,etqjl6s9m9.adobestats.io,AD-BAN
  - DOMAIN,iyuzq3njtk.adobestats.io,AD-BAN
  - DOMAIN,k2zeiskfro.adobestats.io,AD-BAN
  - DOMAIN,kk6mqz4ho1.adobestats.io,AD-BAN
  - DOMAIN,ltby3lmge7.adobestats.io,AD-BAN
  - DOMAIN,m07jtnnega.adobestats.io,AD-BAN
  - DOMAIN,o9617jdaiw.adobestats.io,AD-BAN
  - DOMAIN,ry9atn2zzw.adobestats.io,AD-BAN
  - DOMAIN,t8nxhdgbcb.adobestats.io,AD-BAN
  - DOMAIN,yhxcdjy2st.adobestats.io,AD-BAN
  - DOMAIN,1yzch4f7fj.adobestats.io,AD-BAN
  - DOMAIN,2dym9ld8t4.adobestats.io,AD-BAN
  - DOMAIN,7857z7jy1n.adobestats.io,AD-BAN
  - DOMAIN,917wzppd6w.adobestats.io,AD-BAN
  - DOMAIN,acakpm3wmd.adobestats.io,AD-BAN
  - DOMAIN,ah0uf3uzwe.adobestats.io,AD-BAN
  - DOMAIN,anllgxlrgl.adobestats.io,AD-BAN
  - DOMAIN,ar3zpq1idw.adobestats.io,AD-BAN
  - DOMAIN,as15ffplma.adobestats.io,AD-BAN
  - DOMAIN,b343x3kjgp.adobestats.io,AD-BAN
  - DOMAIN,b4ur7jk78w.adobestats.io,AD-BAN
  - DOMAIN,c7udtzsk2j.adobestats.io,AD-BAN
  - DOMAIN,dt549nqpx7.adobestats.io,AD-BAN
  - DOMAIN,f7ul6vs4ha.adobestats.io,AD-BAN
  - DOMAIN,hbejpf1qou.adobestats.io,AD-BAN
  - DOMAIN,s6195z8x2q.adobestats.io,AD-BAN
  - DOMAIN,smtcbgh2n7.adobestats.io,AD-BAN
  - DOMAIN,v5f89yjtcw.adobestats.io,AD-BAN
  - DOMAIN,x66v4qn2t7.adobestats.io,AD-BAN
  - DOMAIN,yvbzqwn2gz.adobestats.io,AD-BAN
  - DOMAIN,1ompyaokc3.adobestats.io,AD-BAN
  - DOMAIN,2ent6j0ret.adobestats.io,AD-BAN
  - DOMAIN,7860w7avqe.adobestats.io,AD-BAN
  - DOMAIN,kqs7x93q8r.adobestats.io,AD-BAN
  - DOMAIN,now8wpo1bv.adobestats.io,AD-BAN
  - DOMAIN,oeab9s6dtf.adobestats.io,AD-BAN
  - DOMAIN,p4apxcgh7b.adobestats.io,AD-BAN
  - DOMAIN,rs2deio0ks.adobestats.io,AD-BAN
  - DOMAIN,wfyeckyxxx.adobestats.io,AD-BAN
  - DOMAIN,xngv0345gb.adobestats.io,AD-BAN
  - DOMAIN,5nae7ued1i.adobestats.io,AD-BAN
  - DOMAIN,74jqw6xdam.adobestats.io,AD-BAN
  - DOMAIN,9xxyu4ncc9.adobestats.io,AD-BAN
  - DOMAIN,ckh0swnp4c.adobestats.io,AD-BAN
  - DOMAIN,dr02lso5fh.adobestats.io,AD-BAN
  - DOMAIN,et3x020m0i.adobestats.io,AD-BAN
  - DOMAIN,g58jqxdh3y.adobestats.io,AD-BAN
  - DOMAIN,j7wq25n7dy.adobestats.io,AD-BAN
  - DOMAIN,a69wv3f4j3.adobestats.io,AD-BAN
  - DOMAIN,jwi6q78hu2.adobestats.io,AD-BAN
  - DOMAIN,nw3ft2wlrn.adobestats.io,AD-BAN
  - DOMAIN,yykww43js1.adobestats.io,AD-BAN
  - DOMAIN,12ihfrf869.adobestats.io,AD-BAN
  - DOMAIN,a5dtr1c4er.adobestats.io,AD-BAN
  - DOMAIN,ajs31fsy2t.adobestats.io,AD-BAN
  - DOMAIN,mi9rav314a.adobestats.io,AD-BAN
  - DOMAIN,z66m01zo11.adobestats.io,AD-BAN
  - DOMAIN,vd8bjo50bv.adobestats.io,AD-BAN
  - DOMAIN,tqcbs617dw.adobe.io,AD-BAN
  - DOMAIN,fcbx058i0c.adobe.io,AD-BAN
  - DOMAIN,chlydkc9bz.adobe.io,AD-BAN
  - DOMAIN,4f1b1vqcfi.adobestats.io,AD-BAN
  - DOMAIN,ci5yrifbog.adobestats.io,AD-BAN
  - DOMAIN,vn4waib0dk.adobestats.io,AD-BAN
  - DOMAIN,drdqxhlcop.adobe.io,AD-BAN
  - DOMAIN,1i09xck9hj.adobestats.io,AD-BAN
  - DOMAIN,3reg39xtkp.adobestats.io,AD-BAN
  - DOMAIN,quij2u03a1.adobestats.io,AD-BAN
  - DOMAIN,xo9j8bcw4a.adobe.io,AD-BAN
  - DOMAIN,37c3yfb1t4.adobestats.io,AD-BAN
  - DOMAIN,72xoz2f3v6.adobestats.io,AD-BAN
  - DOMAIN,be26lkdm4q.adobestats.io,AD-BAN
  - DOMAIN,y9n9ngtvna.adobestats.io,AD-BAN
  - DOMAIN,4psx0dt6zg.adobestats.io,AD-BAN
  - DOMAIN,6pv0uu0vny.adobestats.io,AD-BAN
  - DOMAIN,9b2hch4xc9.adobestats.io,AD-BAN
  - DOMAIN,9wbdpkyfsz.adobestats.io,AD-BAN
  - DOMAIN,ekt43qq0wo.adobestats.io,AD-BAN
  - DOMAIN,h1xtbu1sca.adobestats.io,AD-BAN
  - DOMAIN,hdym10nr7u.adobestats.io,AD-BAN
  - DOMAIN,hmnzwq6owm.adobestats.io,AD-BAN
  - DOMAIN,hvww1kah7v.adobestats.io,AD-BAN
  - DOMAIN,jkt1n3vsxr.adobestats.io,AD-BAN
  - DOMAIN,nth06aynso.adobestats.io,AD-BAN
  - DOMAIN,q4ajvptsj7.adobestats.io,AD-BAN
  - DOMAIN,t8ckmbunss.adobestats.io,AD-BAN
  - DOMAIN,x1mmbszh12.adobestats.io,AD-BAN
  - DOMAIN,y8x0fb0tdr.adobestats.io,AD-BAN
  - DOMAIN,hy1ykx5mvp.adobestats.io,AD-BAN
  - DOMAIN,yl2744311i.adobestats.io,AD-BAN
  - DOMAIN,fuindpvfok.adobestats.io,AD-BAN
  - DOMAIN,699yxd2304.adobestats.io,AD-BAN
  - DOMAIN,6t47fd4rda.adobestats.io,AD-BAN
  - DOMAIN,lpm2ewb43r.adobestats.io,AD-BAN
  - DOMAIN,mktnq8n4qv.adobestats.io,AD-BAN
  - DOMAIN,xuk3z0wfkn.adobestats.io,AD-BAN
  - DOMAIN,1s97z9hn4o.adobestats.io,AD-BAN
  - DOMAIN,fmbxa3a0yh.adobestats.io,AD-BAN
  - DOMAIN,ywwlnskz2q.adobestats.io,AD-BAN
  - DOMAIN,a2104gz1mh.adobe.io,AD-BAN
  - DOMAIN,0ojupfm51u.adobe.io,AD-BAN
  - DOMAIN,4zong3qp04.adobestats.io,AD-BAN
  - DOMAIN,giq5q50mql.adobestats.io,AD-BAN
  - DOMAIN,vs8cvtxb6h.adobestats.io,AD-BAN
  - DOMAIN,3f3h0nltvv.adobestats.io,AD-BAN
  - DOMAIN,9f0nec97jl.adobestats.io,AD-BAN
  - DOMAIN,a781lq3dl1.adobestats.io,AD-BAN
  - DOMAIN,cqtur9nf2j.adobestats.io,AD-BAN
  - DOMAIN,d13qjllccx.adobestats.io,AD-BAN
  - DOMAIN,e94c9o627h.adobestats.io,AD-BAN
  - DOMAIN,g25js6o5zn.adobestats.io,AD-BAN
  - DOMAIN,grzjv3nyau.adobestats.io,AD-BAN
  - DOMAIN,j0c7zaivwa.adobestats.io,AD-BAN
  - DOMAIN,j7d199wwp8.adobestats.io,AD-BAN
  - DOMAIN,o75l4dlkbh.adobestats.io,AD-BAN
  - DOMAIN,sgg0nltplg.adobestats.io,AD-BAN
  - DOMAIN,uiktuww26f.adobestats.io,AD-BAN
  - DOMAIN,wojee26p4t.adobestats.io,AD-BAN
  - DOMAIN,xm0yibvxj5.adobestats.io,AD-BAN
  - DOMAIN,y1usv3l35k.adobestats.io,AD-BAN
  - DOMAIN,yaxvhurwoa.adobestats.io,AD-BAN
  - DOMAIN,1w46mavare.adobestats.io,AD-BAN
  - DOMAIN,lhdf90vxbv.adobestats.io,AD-BAN
  - DOMAIN,wrtafci7rp.adobestats.io,AD-BAN
  - DOMAIN,4f8y6z3snu.adobestats.io,AD-BAN
  - DOMAIN,frkjjsdxae.adobestats.io,AD-BAN
  - DOMAIN,iahl4jjb56.adobestats.io,AD-BAN
  - DOMAIN,t5k3ioz4p2.adobestats.io,AD-BAN
  - DOMAIN,5fw2aensgd.adobestats.io,AD-BAN
  - DOMAIN,c8epvys0ps.adobestats.io,AD-BAN
  - DOMAIN,rr9nn5x1fh.adobestats.io,AD-BAN
  - DOMAIN,ubxajwohoi.adobestats.io,AD-BAN
  - DOMAIN,gsd14enp3n.adobestats.io,AD-BAN
  - DOMAIN,rshw2d4xt2.adobestats.io,AD-BAN
  - DOMAIN,a43dmjfhi6.adobestats.io,AD-BAN
  - DOMAIN,5rzen92rqw.adobestats.io,AD-BAN
  - DOMAIN,zhsq65iox8.adobestats.io,AD-BAN
  - DOMAIN,5249gprdc8.adobestats.io,AD-BAN
  - DOMAIN,5yhf2ygy0v.adobestats.io,AD-BAN
  - DOMAIN,64aui0lmm8.adobestats.io,AD-BAN
  - DOMAIN,9ksdhwfj1i.adobestats.io,AD-BAN
  - DOMAIN,ay4wu1tp41.adobestats.io,AD-BAN
  - DOMAIN,e3ddirlhb0.adobestats.io,AD-BAN
  - DOMAIN,huk9szui57.adobestats.io,AD-BAN
  - DOMAIN,kvew1ycx60.adobestats.io,AD-BAN
  - DOMAIN,l3t2s6mj4w.adobestats.io,AD-BAN
  - DOMAIN,mr9hl8gv47.adobestats.io,AD-BAN
  - DOMAIN,n8lqv6j4yr.adobestats.io,AD-BAN
  - DOMAIN,omx332339b.adobestats.io,AD-BAN
  - DOMAIN,sas2o2lo36.adobestats.io,AD-BAN
  - DOMAIN,vgieu16g7s.adobestats.io,AD-BAN
  - DOMAIN,w25ijw4ebd.adobestats.io,AD-BAN
  - DOMAIN,wyxrzcfpte.adobestats.io,AD-BAN
  - DOMAIN,93up6jlw8l.adobestats.io,AD-BAN
  - DOMAIN,ui5m4exlcw.adobestats.io,AD-BAN
  - DOMAIN,04jkjo2db5.adobestats.io,AD-BAN
  - DOMAIN,20x112xlz4.adobestats.io,AD-BAN
  - DOMAIN,osp3g9p4c9.adobestats.io,AD-BAN
  - DOMAIN,dmi13b9vlo.adobestats.io,AD-BAN
  - DOMAIN,pndiszyo9k.adobestats.io,AD-BAN
  - DOMAIN,f162lqu11i.adobestats.io,AD-BAN
  - DOMAIN,4u4udfpb9h.adobe.io,AD-BAN
  - DOMAIN,oz5i3yutuw.adobestats.io,AD-BAN
  - DOMAIN,dn0sbkqqfk.adobestats.io,AD-BAN
  - DOMAIN,ed3bl6kidt.adobestats.io,AD-BAN
  - DOMAIN,kw2z4tkbb6.adobestats.io,AD-BAN
  - DOMAIN,v7jyeimrye.adobestats.io,AD-BAN
  - DOMAIN,y6950iur2g.adobestats.io,AD-BAN
  - DOMAIN,9k046300lp.adobe.io,AD-BAN
  - DOMAIN,rzrxmjzfdn.adobestats.io,AD-BAN
  - DOMAIN,ef7m2t2zz9.adobestats.io,AD-BAN
  - DOMAIN,5tlyaxuuph.adobestats.io,AD-BAN
  - DOMAIN,b37k7g9c3q.adobestats.io,AD-BAN
  - DOMAIN,h4eiodaymd.adobestats.io,AD-BAN
  - DOMAIN,vyho44iygi.adobestats.io,AD-BAN
  - DOMAIN,3kqudwluux.adobestats.io,AD-BAN
  - DOMAIN,4g1n9wc25y.adobestats.io,AD-BAN
  - DOMAIN,4z1zypgkef.adobestats.io,AD-BAN
  - DOMAIN,548g5qdx3a.adobestats.io,AD-BAN
  - DOMAIN,9v2nxvmwto.adobestats.io,AD-BAN
  - DOMAIN,ewcovphpsa.adobestats.io,AD-BAN
  - DOMAIN,k0at187jqk.adobestats.io,AD-BAN
  - DOMAIN,r0xv19ou69.adobestats.io,AD-BAN
  - DOMAIN,ujzflw123x.adobestats.io,AD-BAN
  - DOMAIN,vx9xh18ov9.adobestats.io,AD-BAN
  - DOMAIN,wvyb3i4jf9.adobestats.io,AD-BAN
  - DOMAIN,xcna71ygzo.adobestats.io,AD-BAN
  - DOMAIN,zsursdyz0d.adobestats.io,AD-BAN
  - DOMAIN,idd3z8uis9.adobestats.io,AD-BAN
  - DOMAIN,xeh65lseqp.adobestats.io,AD-BAN
  - DOMAIN,htyt9ah5l0.adobestats.io,AD-BAN
  - DOMAIN,ld090pbtrm.adobestats.io,AD-BAN
  - DOMAIN,9c7tz4k81b.adobestats.io,AD-BAN
  - DOMAIN,c0acub5mul.adobestats.io,AD-BAN
  - DOMAIN,z06nr7yct1.adobestats.io,AD-BAN
  - DOMAIN,p1ev0qf92u.adobestats.io,AD-BAN
  - DOMAIN,rnkix8uugk.adobestats.io,AD-BAN
  - DOMAIN,xu2ws3lrz4.adobestats.io,AD-BAN
  - DOMAIN,yjry12zotn.adobestats.io,AD-BAN
  - DOMAIN,atn3a2qrbo.adobestats.io,AD-BAN
  - DOMAIN,hl0f6tmk0r.adobestats.io,AD-BAN
  - DOMAIN,3mmyrmpxdx.adobestats.io,AD-BAN
  - DOMAIN,8burj9rb4s.adobestats.io,AD-BAN
  - DOMAIN,8ondwicgpd.adobestats.io,AD-BAN
  - DOMAIN,i48sv1cxi0.adobestats.io,AD-BAN
  - DOMAIN,0qnxjg7wfg.adobestats.io,AD-BAN
  - DOMAIN,wzn00xy2ww.adobestats.io,AD-BAN
  - DOMAIN,1oh17981n9.adobestats.io,AD-BAN
  - DOMAIN,63rbu8oiz9.adobestats.io,AD-BAN
  - DOMAIN,674gbmmxoi.adobestats.io,AD-BAN
  - DOMAIN,a89bum3ple.adobestats.io,AD-BAN
  - DOMAIN,ck6vzx58v4.adobestats.io,AD-BAN
  - DOMAIN,djrnrt8f6t.adobestats.io,AD-BAN
  - DOMAIN,h6o050q9pf.adobestats.io,AD-BAN
  - DOMAIN,kfej9govhz.adobestats.io,AD-BAN
  - DOMAIN,fipjog5p8f.adobestats.io,AD-BAN
  - DOMAIN,53q3ombk2r.adobestats.io,AD-BAN
  - DOMAIN,7w7gpbzc77.adobestats.io,AD-BAN
  - DOMAIN,9xjyqha9e9.adobestats.io,AD-BAN
  - DOMAIN,jyu43b655u.adobestats.io,AD-BAN
  - DOMAIN,o8xhlbmm82.adobestats.io,AD-BAN
  - DOMAIN,zlzdicvb1y.adobestats.io,AD-BAN
  - DOMAIN,5bcixfkyl5.adobestats.io,AD-BAN
  - DOMAIN,fu4rpw9ku4.adobestats.io,AD-BAN
  - DOMAIN,h4wgsqts2k.adobestats.io,AD-BAN
  - DOMAIN,qlw1ee8xzn.adobestats.io,AD-BAN
  - DOMAIN,wgg7g1om7h.adobestats.io,AD-BAN
  - DOMAIN,wozkyv628d.adobestats.io,AD-BAN
  - DOMAIN,kw31bz1lwj.adobestats.io,AD-BAN
  - DOMAIN,666jnxks4d.adobestats.io,AD-BAN
  - DOMAIN,wujfm82qyd.adobestats.io,AD-BAN
  - DOMAIN,vgetwxoqno.adobe.io,AD-BAN
  - DOMAIN,12zow70qyg.adobestats.io,AD-BAN
  - DOMAIN,17rznd8ped.adobestats.io,AD-BAN
  - DOMAIN,1mqvqabmi0.adobestats.io,AD-BAN
  - DOMAIN,86r5sgpc5i.adobestats.io,AD-BAN
  - DOMAIN,9aa2r7kikj.adobestats.io,AD-BAN
  - DOMAIN,ecdcuflr6b.adobestats.io,AD-BAN
  - DOMAIN,g3x2gf65lr.adobestats.io,AD-BAN
  - DOMAIN,h97lgqk8bo.adobestats.io,AD-BAN
  - DOMAIN,jv4pl10h5s.adobestats.io,AD-BAN
  - DOMAIN,jzh1rdq07h.adobestats.io,AD-BAN
  - DOMAIN,ou6wlq2xxk.adobestats.io,AD-BAN
  - DOMAIN,p2hljfs4ui.adobestats.io,AD-BAN
  - DOMAIN,p5lr643921.adobestats.io,AD-BAN
  - DOMAIN,p882on2mec.adobestats.io,AD-BAN
  - DOMAIN,qrz7h0bk0d.adobestats.io,AD-BAN
  - DOMAIN,tpa7l912ct.adobestats.io,AD-BAN
  - DOMAIN,utl2ryss9g.adobestats.io,AD-BAN
  - DOMAIN,y8nrk9ev78.adobestats.io,AD-BAN
  - DOMAIN,yabyd58pwe.adobestats.io,AD-BAN
  - DOMAIN,yvz37f39o9.adobestats.io,AD-BAN
  - DOMAIN,z9cyo99ees.adobestats.io,AD-BAN
  - DOMAIN,eljpnp7pwp.adobestats.io,AD-BAN
  - DOMAIN,9cq4sjum6s.adobestats.io,AD-BAN
  - DOMAIN,f34mf655aw.adobestats.io,AD-BAN
  - DOMAIN,m4ldtnfvqf.adobestats.io,AD-BAN
  - DOMAIN,3uzm9qfpzw.adobestats.io,AD-BAN
  - DOMAIN,otoaq2y6ha.adobestats.io,AD-BAN
  - DOMAIN,w2tarrtw8t.adobestats.io,AD-BAN
  - DOMAIN,5ehqhq0kgt.adobestats.io,AD-BAN
  - DOMAIN,avwgpydcaz.adobestats.io,AD-BAN
  - DOMAIN,t45y99rpkr.adobestats.io,AD-BAN
  - DOMAIN,7zjom7dijk.adobestats.io,AD-BAN
  - DOMAIN,10a3hujicl.adobestats.io,AD-BAN
  - DOMAIN,5ebbalr27t.adobestats.io,AD-BAN
  - DOMAIN,ai51k25vkp.adobestats.io,AD-BAN
  - DOMAIN,flutt9urxr.adobestats.io,AD-BAN
  - DOMAIN,hpbpvpzb2l.adobestats.io,AD-BAN
  - DOMAIN,jfpuemxvzl.adobestats.io,AD-BAN
  - DOMAIN,lphlawf194.adobestats.io,AD-BAN
  - DOMAIN,m0o17z9ytf.adobestats.io,AD-BAN
  - DOMAIN,s9la1nxlf1.adobestats.io,AD-BAN
  - DOMAIN,5ldhuv8nzy.adobestats.io,AD-BAN
  - DOMAIN,fpaodyl985.adobestats.io,AD-BAN
  - DOMAIN,fypusvplon.adobestats.io,AD-BAN
  - DOMAIN,hgdvggfsuo.adobestats.io,AD-BAN
  - DOMAIN,hnskhe2spg.adobestats.io,AD-BAN
  - DOMAIN,ixlleed9m6.adobestats.io,AD-BAN
  - DOMAIN,mbksaqsgke.adobestats.io,AD-BAN
  - DOMAIN,puk5mdqkx8.adobestats.io,AD-BAN
  - DOMAIN,q11bco3ezj.adobestats.io,AD-BAN
  - DOMAIN,z9d0725u9r.adobestats.io,AD-BAN
  - DOMAIN,bmfyyt6q6g.adobestats.io,AD-BAN
  - DOMAIN,og6u0rueid.adobestats.io,AD-BAN
  - DOMAIN,8i88bcggu6.adobestats.io,AD-BAN
  - DOMAIN,b0qyzgkxcv.adobestats.io,AD-BAN
  - DOMAIN,h0no575qji.adobestats.io,AD-BAN
  - DOMAIN,j2ktcg967p.adobestats.io,AD-BAN
  - DOMAIN,qv3lfs30zn.adobestats.io,AD-BAN
  - DOMAIN,azrbt1iw3j.adobestats.io,AD-BAN
  - DOMAIN,igka06iww4.adobestats.io,AD-BAN
  - DOMAIN,zqby5krery.adobestats.io,AD-BAN
  - DOMAIN,27hqwvagdh.adobe.io,AD-BAN
  - DOMAIN,m6t8sobbc7.adobestats.io,AD-BAN
  - DOMAIN,1k7hno3xrp.adobestats.io,AD-BAN
  - DOMAIN,bw59wxr92v.adobestats.io,AD-BAN
  - DOMAIN,dj06zaouol.adobestats.io,AD-BAN
  - DOMAIN,kgj7bmte19.adobestats.io,AD-BAN
  - DOMAIN,kjbqf1ol9g.adobestats.io,AD-BAN
  - DOMAIN,m1vtal0vxi.adobestats.io,AD-BAN
  - DOMAIN,mmu7w9z4g7.adobestats.io,AD-BAN
  - DOMAIN,rrwch5wg04.adobestats.io,AD-BAN
  - DOMAIN,33dghav1u0.adobestats.io,AD-BAN
  - DOMAIN,3eamcreuvn.adobestats.io,AD-BAN
  - DOMAIN,49xq1olxsn.adobestats.io,AD-BAN
  - DOMAIN,5ywl5monp9.adobestats.io,AD-BAN
  - DOMAIN,9lbrsj3eqc.adobestats.io,AD-BAN
  - DOMAIN,bn4i1jgarl.adobestats.io,AD-BAN
  - DOMAIN,dio7fli6oc.adobestats.io,AD-BAN
  - DOMAIN,e4xy0my9e4.adobestats.io,AD-BAN
  - DOMAIN,ol8cco0yne.adobestats.io,AD-BAN
  - DOMAIN,p8seks0alh.adobestats.io,AD-BAN
  - DOMAIN,pf2jezndie.adobestats.io,AD-BAN
  - DOMAIN,tbo1621jaj.adobestats.io,AD-BAN
  - DOMAIN,yf9inv4f4a.adobestats.io,AD-BAN
  - DOMAIN,46si8xsrd4.adobestats.io,AD-BAN
  - DOMAIN,gxxj3ht33q.adobestats.io,AD-BAN
  - DOMAIN,ry5dhsrn9q.adobestats.io,AD-BAN
  - DOMAIN,4anjyeritg.adobestats.io,AD-BAN
  - DOMAIN,7tt98n5vr9.adobestats.io,AD-BAN
  - DOMAIN,k6bbumjg3j.adobestats.io,AD-BAN
  - DOMAIN,s7hxmji3fg.adobestats.io,AD-BAN
  - DOMAIN,w7wnvpf6it.adobestats.io,AD-BAN
  - DOMAIN,85zgeugwrx.adobestats.io,AD-BAN
  - DOMAIN,mbya1atovd.adobestats.io,AD-BAN
  - DOMAIN,2q9nqd24at.adobestats.io,AD-BAN
  - DOMAIN,bfe030zu1d.adobestats.io,AD-BAN
  - DOMAIN,bgu5bafji4.adobestats.io,AD-BAN
  - DOMAIN,canp69iyvw.adobestats.io,AD-BAN
  - DOMAIN,d5qylk77uu.adobestats.io,AD-BAN
  - DOMAIN,j0o3f8hx58.adobestats.io,AD-BAN
  - DOMAIN,m9320z1xwy.adobestats.io,AD-BAN
  - DOMAIN,srqwgyza90.adobestats.io,AD-BAN
  - DOMAIN,4e0e132d50.adobestats.io,AD-BAN
  - DOMAIN,7hy5neh7yd.adobestats.io,AD-BAN
  - DOMAIN,7up2et2elb.adobestats.io,AD-BAN
  - DOMAIN,8u23q07fai.adobestats.io,AD-BAN
  - DOMAIN,a4o6j6a60q.adobestats.io,AD-BAN
  - DOMAIN,cj75c7xu81.adobestats.io,AD-BAN
  - DOMAIN,ephqb5mlx2.adobestats.io,AD-BAN
  - DOMAIN,lc990on4y4.adobestats.io,AD-BAN
  - DOMAIN,lma74hsgmt.adobestats.io,AD-BAN
  - DOMAIN,oxebixf9bp.adobestats.io,AD-BAN
  - DOMAIN,pznf2cvokl.adobestats.io,AD-BAN
  - DOMAIN,v06zqmu5pk.adobestats.io,AD-BAN
  - DOMAIN,7cl578y97h.adobestats.io,AD-BAN
  - DOMAIN,8vf1533hg0.adobestats.io,AD-BAN
  - DOMAIN,j065cjonho.adobestats.io,AD-BAN
  - DOMAIN,gkuhot62li.adobestats.io,AD-BAN
  - DOMAIN,3jxakfyart.adobestats.io,AD-BAN
  - DOMAIN,eilhhpyrhk.adobestats.io,AD-BAN
  - DOMAIN,fi07tozbmh.adobestats.io,AD-BAN
  - DOMAIN,int03thy3s.adobestats.io,AD-BAN
  - DOMAIN,sk3nb074wt.adobestats.io,AD-BAN
  - DOMAIN,k5hez87wo3.adobestats.io,AD-BAN
  - DOMAIN,z8bpa11zz5.adobestats.io,AD-BAN
  - DOMAIN,op6ya9mf18.adobestats.io,AD-BAN
  - DOMAIN,p9jaddiqux.adobe.io,AD-BAN
  - DOMAIN,0mgqdi537f.adobestats.io,AD-BAN
  - DOMAIN,224me58l5q.adobestats.io,AD-BAN
  - DOMAIN,37ng6po6bp.adobestats.io,AD-BAN
  - DOMAIN,8mt9obctot.adobestats.io,AD-BAN
  - DOMAIN,aen6torhir.adobestats.io,AD-BAN
  - DOMAIN,dnqofyouwm.adobestats.io,AD-BAN
  - DOMAIN,h1sp8k6bhv.adobestats.io,AD-BAN
  - DOMAIN,hnebe5wyyy.adobestats.io,AD-BAN
  - DOMAIN,s8cxczmvh5.adobestats.io,AD-BAN
  - DOMAIN,v7yl9ajfg9.adobestats.io,AD-BAN
  - DOMAIN,wvfhx4enq4.adobestats.io,AD-BAN
  - DOMAIN,1s0s64nq7w.adobestats.io,AD-BAN
  - DOMAIN,9uxtpeji2v.adobestats.io,AD-BAN
  - DOMAIN,be4jspokx2.adobestats.io,AD-BAN
  - DOMAIN,r7x9tbvsvx.adobestats.io,AD-BAN
  - DOMAIN,w20hk05cgp.adobestats.io,AD-BAN
  - DOMAIN,x915sjr4n9.adobestats.io,AD-BAN
  - DOMAIN,xoq8wwlhsp.adobestats.io,AD-BAN
  - DOMAIN,64a4g05fmn.adobestats.io,AD-BAN
  - DOMAIN,6j5lc5swyh.adobestats.io,AD-BAN
  - DOMAIN,xwr6ju22ai.adobestats.io,AD-BAN
  - DOMAIN,1o54s13pxf.adobestats.io,AD-BAN
  - DOMAIN,4ypokgsgmb.adobestats.io,AD-BAN
  - DOMAIN,dvndpazg45.adobestats.io,AD-BAN
  - DOMAIN,eyp31zax99.adobestats.io,AD-BAN
  - DOMAIN,g059w52e5a.adobestats.io,AD-BAN
  - DOMAIN,p9t0tf8p73.adobestats.io,AD-BAN
  - DOMAIN,vyso4gf2fo.adobestats.io,AD-BAN
  - DOMAIN,ytm4prvsic.adobestats.io,AD-BAN
  - DOMAIN,3yx324cjrc.adobestats.io,AD-BAN
  - DOMAIN,zarflqrb4e.adobestats.io,AD-BAN
  - DOMAIN,u8dy2x6ofx.adobestats.io,AD-BAN
  - DOMAIN,d9u8iw3ec6.adobestats.io,AD-BAN
  - DOMAIN,8ksw9jeglo.adobestats.io,AD-BAN
  - DOMAIN,av91c4swlr.adobestats.io,AD-BAN
  - DOMAIN,nhijoow8u9.adobestats.io,AD-BAN
  - DOMAIN,ukl1tj2nvv.adobestats.io,AD-BAN
  - DOMAIN,w76a6nm3fs.adobestats.io,AD-BAN
  - DOMAIN,2uzp2kpn5r.adobestats.io,AD-BAN
  - DOMAIN,309q77jr8y.adobestats.io,AD-BAN
  - DOMAIN,3cb9jccasz.adobestats.io,AD-BAN
  - DOMAIN,3t80jr3icl.adobestats.io,AD-BAN
  - DOMAIN,46w37ofmyh.adobestats.io,AD-BAN
  - DOMAIN,4br2ud69pv.adobestats.io,AD-BAN
  - DOMAIN,8qq1w94u66.adobestats.io,AD-BAN
  - DOMAIN,fnx5ng6n5k.adobestats.io,AD-BAN
  - DOMAIN,je7b0l8vdo.adobestats.io,AD-BAN
  - DOMAIN,l7imn8j82x.adobestats.io,AD-BAN
  - DOMAIN,mbiowykjov.adobestats.io,AD-BAN
  - DOMAIN,oc64zoqehy.adobestats.io,AD-BAN
  - DOMAIN,r97n5i4gui.adobestats.io,AD-BAN
  - DOMAIN,sn7ul2kyne.adobestats.io,AD-BAN
  - DOMAIN,tz8aenh3nl.adobestats.io,AD-BAN
  - DOMAIN,bv7iaks1q0.adobestats.io,AD-BAN
  - DOMAIN,lmy2aip7t9.adobestats.io,AD-BAN
  - DOMAIN,v1p7zr510j.adobestats.io,AD-BAN
  - DOMAIN,aw725q3eth.adobestats.io,AD-BAN
  - DOMAIN,ltnk9caeyt.adobestats.io,AD-BAN
  - DOMAIN,ykcaj6bh15.adobestats.io,AD-BAN
  - DOMAIN,9ohyfdvj27.adobestats.io,AD-BAN
  - DOMAIN,lmvu17gkya.adobestats.io,AD-BAN
  - DOMAIN,0np4eiuov7.adobestats.io,AD-BAN
  - DOMAIN,6u32mwnaxq.adobestats.io,AD-BAN
  - DOMAIN,d3my5g4jna.adobestats.io,AD-BAN
  - DOMAIN,j8iepl91av.adobestats.io,AD-BAN
  - DOMAIN,no8yw4nh6e.adobestats.io,AD-BAN
  - DOMAIN,nop4h5fp61.adobestats.io,AD-BAN
  - DOMAIN,wvwrj2y0li.adobestats.io,AD-BAN
  - DOMAIN,zxv4wvfvi9.adobestats.io,AD-BAN
  - DOMAIN,2oyz2t4wq9.adobestats.io,AD-BAN
  - DOMAIN,5xnbj0m6t2.adobestats.io,AD-BAN
  - DOMAIN,6asnsetik3.adobestats.io,AD-BAN
  - DOMAIN,hknkvizuc2.adobestats.io,AD-BAN
  - DOMAIN,w8s4afl50t.adobestats.io,AD-BAN
  - DOMAIN,xaggdolnhv.adobestats.io,AD-BAN
  - DOMAIN,0nx23dhzap.adobestats.io,AD-BAN
  - DOMAIN,744jei1415.adobestats.io,AD-BAN
  - DOMAIN,ahuu2xu1ya.adobestats.io,AD-BAN
  - DOMAIN,al76al5u4u.adobestats.io,AD-BAN
  - DOMAIN,fq8re9lavq.adobestats.io,AD-BAN
  - DOMAIN,m38l9rfnry.adobestats.io,AD-BAN
  - DOMAIN,uzantvo0as.adobe.io,AD-BAN
  - DOMAIN,7gag9ygrcx.adobestats.io,AD-BAN
  - DOMAIN,7jg7m1ces4.adobestats.io,AD-BAN
  - DOMAIN,kk0sjamt88.adobestats.io,AD-BAN
  - DOMAIN,xygpp0qk24.adobestats.io,AD-BAN
  - DOMAIN,1kez8509ag.adobestats.io,AD-BAN
  - DOMAIN,ja7czxetms.adobestats.io,AD-BAN
  - DOMAIN,xldcvdx24q.adobestats.io,AD-BAN
  - DOMAIN,f03ibhcdnc.adobestats.io,AD-BAN
  - DOMAIN,cbfqosfuqi.adobestats.io,AD-BAN
  - DOMAIN,f95w5c40ys.adobestats.io,AD-BAN
  - DOMAIN,6mfhu1z5u7.adobestats.io,AD-BAN
  - DOMAIN,b360ay92q3.adobestats.io,AD-BAN
  - DOMAIN,xmmg8xhkjb.adobestats.io,AD-BAN
  - DOMAIN,it86bgy8qf.adobestats.io,AD-BAN
  - DOMAIN,ecsdxf3wl3.adobestats.io,AD-BAN
  - DOMAIN,3ivg7wus63.adobestats.io,AD-BAN
  - DOMAIN,nqnnfmo9od.adobestats.io,AD-BAN
  - DOMAIN,08g6cm4kaq.adobestats.io,AD-BAN
  - DOMAIN,32gijtiveo.adobestats.io,AD-BAN
  - DOMAIN,7i8vjvlwuc.adobestats.io,AD-BAN
  - DOMAIN,8bm7q3s69i.adobestats.io,AD-BAN
  - DOMAIN,9lz057fho1.adobestats.io,AD-BAN
  - DOMAIN,9oyru5uulx.adobestats.io,AD-BAN
  - DOMAIN,dwv18zn96z.adobestats.io,AD-BAN
  - DOMAIN,faag4y3x73.adobestats.io,AD-BAN
  - DOMAIN,jtc0fjhor2.adobestats.io,AD-BAN
  - DOMAIN,mkzec8b0pu.adobestats.io,AD-BAN
  - DOMAIN,nv8ysttp93.adobestats.io,AD-BAN
  - DOMAIN,rp9pax976k.adobestats.io,AD-BAN
  - DOMAIN,tzd44dufds.adobestats.io,AD-BAN
  - DOMAIN,w1tw8nuikr.adobestats.io,AD-BAN
  - DOMAIN,wdk81mqjw2.adobestats.io,AD-BAN
  - DOMAIN,xu0fl2f2fa.adobestats.io,AD-BAN
  - DOMAIN,fel2ajqj6q.adobestats.io,AD-BAN
  - DOMAIN,szlpwlqsj9.adobestats.io,AD-BAN
  - DOMAIN,1yqnqu95vt.adobestats.io,AD-BAN
  - DOMAIN,2drlj3q5q9.adobestats.io,AD-BAN
  - DOMAIN,6c2odkl2f7.adobestats.io,AD-BAN
  - DOMAIN,dzx1z8to3i.adobestats.io,AD-BAN
  - DOMAIN,8xi6eh0lbe.adobestats.io,AD-BAN
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,SELECT`
}
		
function getpsbConfig(Pswd, hostName) {
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
				"address": "tls:
				"detour": "select"
			  },
			  {
				"tag": "localdns",
				"address": "h3:
				"detour": "direct"
			  },
			  {
				"address": "rcode:
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
          "CF_T8_${IP8}_${PT8}",
          "CF_T9_${IP9}_${PT9}",
          "CF_T10_${IP10}_${PT10}",
          "CF_T11_${IP11}_${PT11}",
          "CF_T12_${IP12}_${PT12}",
          "CF_T13_${IP13}_${PT13}"
          ]
        },
        {
          "server": "${IP8}",
          "server_port": ${PT8},
          "tag": "CF_T8_${IP8}_${PT8}",        
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "trojan",
          "password": "${Pswd}"
        },
        {
          "server": "${IP9}",
          "server_port": ${PT9},
          "tag": "CF_T9_${IP9}_${PT9}", 
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "trojan",
          "password": "${Pswd}"
        },
        {
          "server": "${IP10}",
          "server_port": ${PT10},
          "tag": "CF_T10_${IP10}_${PT10}", 
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "trojan",
          "password": "${Pswd}"
        },
        {
          "server": "${IP11}",
          "server_port": ${PT11},
          "tag": "CF_T11_${IP11}_${PT11}",
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "trojan",
          "password": "${Pswd}"
        },
        {
          "server": "${IP12}",
          "server_port": ${PT12},
          "tag": "CF_T12_${IP12}_${PT12}",
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "trojan",
          "password": "${Pswd}"
        },
        {
          "server": "${IP13}",
          "server_port": ${PT13},
          "tag": "CF_T13_${IP13}_${PT13}",
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "trojan",
          "password": "${Pswd}"
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
          "CF_T8_${IP8}_${PT8}",
          "CF_T9_${IP9}_${PT9}",
          "CF_T10_${IP10}_${PT10}",
          "CF_T11_${IP11}_${PT11}",
          "CF_T12_${IP12}_${PT12}",
          "CF_T13_${IP13}_${PT13}"
          ],
			  "url": "https:
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



(function () {
  "use strict";

  var ERROR = "input is invalid type";
  var WINDOW = typeof window === "object";
  var root = WINDOW ? window : {};
  if (root.JS_SHA256_NO_WINDOW) {
    WINDOW = false;
  }
  var WEB_WORKER = !WINDOW && typeof self === "object";
  var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === "object" && process.versions && process.versions.node;
  if (NODE_JS) {
    root = global;
  } else if (WEB_WORKER) {
    root = self;
  }
  var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === "object" && module.exports;
  var AMD = typeof define === "function" && define.amd;
  var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== "undefined";
  var HEX_CHARS = "0123456789abcdef".split("");
  var EXTRA = [-2147483648, 8388608, 32768, 128];
  var SHIFT = [24, 16, 8, 0];
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
  ];
  var OUTPUT_TYPES = ["hex", "array", "digest", "arrayBuffer"];

  var blocks = [];

  if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
    Array.isArray = function (obj) {
      return Object.prototype.toString.call(obj) === "[object Array]";
    };
  }

  if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
    ArrayBuffer.isView = function (obj) {
      return typeof obj === "object" && obj.buffer && obj.buffer.constructor === ArrayBuffer;
    };
  }

  var createOutputMethod = function (outputType, is224) {
    return function (message) {
      return new Sha256(is224, true).update(message)[outputType]();
    };
  };

  var createMethod = function (is224) {
    var method = createOutputMethod("hex", is224);
    if (NODE_JS) {
      method = nodeWrap(method, is224);
    }
    method.create = function () {
      return new Sha256(is224);
    };
    method.update = function (message) {
      return method.create().update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createOutputMethod(type, is224);
    }
    return method;
  };

  var nodeWrap = function (method, is224) {
    var crypto = require("crypto");
    var Buffer = require("buffer").Buffer;
    var algorithm = is224 ? "sha224" : "sha256";
    var bufferFrom;
    if (Buffer.from && !root.JS_SHA256_NO_BUFFER_FROM) {
      bufferFrom = Buffer.from;
    } else {
      bufferFrom = function (message) {
        return new Buffer(message);
      };
    }
    var nodeMethod = function (message) {
      if (typeof message === "string") {
        return crypto.createHash(algorithm).update(message, "utf8").digest("hex");
      } else {
        if (message === null || message === undefined) {
          throw new Error(ERROR);
        } else if (message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        }
      }
      if (Array.isArray(message) || ArrayBuffer.isView(message) || message.constructor === Buffer) {
        return crypto.createHash(algorithm).update(bufferFrom(message)).digest("hex");
      } else {
        return method(message);
      }
    };
    return nodeMethod;
  };

  var createHmacOutputMethod = function (outputType, is224) {
    return function (key, message) {
      return new HmacSha256(key, is224, true).update(message)[outputType]();
    };
  };

  var createHmacMethod = function (is224) {
    var method = createHmacOutputMethod("hex", is224);
    method.create = function (key) {
      return new HmacSha256(key, is224);
    };
    method.update = function (key, message) {
      return method.create(key).update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createHmacOutputMethod(type, is224);
    }
    return method;
  };

  function Sha256(is224, sharedMemory) {
    if (sharedMemory) {
      blocks[0] =
        blocks[16] =
        blocks[1] =
        blocks[2] =
        blocks[3] =
        blocks[4] =
        blocks[5] =
        blocks[6] =
        blocks[7] =
        blocks[8] =
        blocks[9] =
        blocks[10] =
        blocks[11] =
        blocks[12] =
        blocks[13] =
        blocks[14] =
        blocks[15] =
          0;
      this.blocks = blocks;
    } else {
      this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }

    if (is224) {
      this.h0 = 0xc1059ed8;
      this.h1 = 0x367cd507;
      this.h2 = 0x3070dd17;
      this.h3 = 0xf70e5939;
      this.h4 = 0xffc00b31;
      this.h5 = 0x68581511;
      this.h6 = 0x64f98fa7;
      this.h7 = 0xbefa4fa4;
    } else {
      
      this.h0 = 0x6a09e667;
      this.h1 = 0xbb67ae85;
      this.h2 = 0x3c6ef372;
      this.h3 = 0xa54ff53a;
      this.h4 = 0x510e527f;
      this.h5 = 0x9b05688c;
      this.h6 = 0x1f83d9ab;
      this.h7 = 0x5be0cd19;
    }

    this.block = this.start = this.bytes = this.hBytes = 0;
    this.finalized = this.hashed = false;
    this.first = true;
    this.is224 = is224;
  }

  Sha256.prototype.update = function (message) {
    if (this.finalized) {
      return;
    }
    var notString,
      type = typeof message;
    if (type !== "string") {
      if (type === "object") {
        if (message === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        } else if (!Array.isArray(message)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
      notString = true;
    }
    var code,
      index = 0,
      i,
      length = message.length,
      blocks = this.blocks;
    while (index < length) {
      if (this.hashed) {
        this.hashed = false;
        blocks[0] = this.block;
        this.block =
          blocks[16] =
          blocks[1] =
          blocks[2] =
          blocks[3] =
          blocks[4] =
          blocks[5] =
          blocks[6] =
          blocks[7] =
          blocks[8] =
          blocks[9] =
          blocks[10] =
          blocks[11] =
          blocks[12] =
          blocks[13] =
          blocks[14] =
          blocks[15] =
            0;
      }

      if (notString) {
        for (i = this.start; index < length && i < 64; ++index) {
          blocks[i >>> 2] |= message[index] << SHIFT[i++ & 3];
        }
      } else {
        for (i = this.start; index < length && i < 64; ++index) {
          code = message.charCodeAt(index);
          if (code < 0x80) {
            blocks[i >>> 2] |= code << SHIFT[i++ & 3];
          } else if (code < 0x800) {
            blocks[i >>> 2] |= (0xc0 | (code >>> 6)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else if (code < 0xd800 || code >= 0xe000) {
            blocks[i >>> 2] |= (0xe0 | (code >>> 12)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else {
            code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
            blocks[i >>> 2] |= (0xf0 | (code >>> 18)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 12) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          }
        }
      }

      this.lastByteIndex = i;
      this.bytes += i - this.start;
      if (i >= 64) {
        this.block = blocks[16];
        this.start = i - 64;
        this.hash();
        this.hashed = true;
      } else {
        this.start = i;
      }
    }
    if (this.bytes > 4294967295) {
      this.hBytes += (this.bytes / 4294967296) << 0;
      this.bytes = this.bytes % 4294967296;
    }
    return this;
  };

  Sha256.prototype.finalize = function () {
    if (this.finalized) {
      return;
    }
    this.finalized = true;
    var blocks = this.blocks,
      i = this.lastByteIndex;
    blocks[16] = this.block;
    blocks[i >>> 2] |= EXTRA[i & 3];
    this.block = blocks[16];
    if (i >= 56) {
      if (!this.hashed) {
        this.hash();
      }
      blocks[0] = this.block;
      blocks[16] =
        blocks[1] =
        blocks[2] =
        blocks[3] =
        blocks[4] =
        blocks[5] =
        blocks[6] =
        blocks[7] =
        blocks[8] =
        blocks[9] =
        blocks[10] =
        blocks[11] =
        blocks[12] =
        blocks[13] =
        blocks[14] =
        blocks[15] =
          0;
    }
    blocks[14] = (this.hBytes << 3) | (this.bytes >>> 29);
    blocks[15] = this.bytes << 3;
    this.hash();
  };

  Sha256.prototype.hash = function () {
    var a = this.h0,
      b = this.h1,
      c = this.h2,
      d = this.h3,
      e = this.h4,
      f = this.h5,
      g = this.h6,
      h = this.h7,
      blocks = this.blocks,
      j,
      s0,
      s1,
      maj,
      t1,
      t2,
      ch,
      ab,
      da,
      cd,
      bc;

    for (j = 16; j < 64; ++j) {
      
      t1 = blocks[j - 15];
      s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
      t1 = blocks[j - 2];
      s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
      blocks[j] = (blocks[j - 16] + s0 + blocks[j - 7] + s1) << 0;
    }

    bc = b & c;
    for (j = 0; j < 64; j += 4) {
      if (this.first) {
        if (this.is224) {
          ab = 300032;
          t1 = blocks[0] - 1413257819;
          h = (t1 - 150054599) << 0;
          d = (t1 + 24177077) << 0;
        } else {
          ab = 704751109;
          t1 = blocks[0] - 210244248;
          h = (t1 - 1521486534) << 0;
          d = (t1 + 143694565) << 0;
        }
        this.first = false;
      } else {
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ab = a & b;
        maj = ab ^ (a & c) ^ bc;
        ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + K[j] + blocks[j];
        t2 = s0 + maj;
        h = (d + t1) << 0;
        d = (t1 + t2) << 0;
      }
      s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
      s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
      da = d & a;
      maj = da ^ (d & b) ^ ab;
      ch = (h & e) ^ (~h & f);
      t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
      t2 = s0 + maj;
      g = (c + t1) << 0;
      c = (t1 + t2) << 0;
      s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
      s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
      cd = c & d;
      maj = cd ^ (c & a) ^ da;
      ch = (g & h) ^ (~g & e);
      t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
      t2 = s0 + maj;
      f = (b + t1) << 0;
      b = (t1 + t2) << 0;
      s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
      s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
      bc = b & c;
      maj = bc ^ (b & d) ^ cd;
      ch = (f & g) ^ (~f & h);
      t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
      t2 = s0 + maj;
      e = (a + t1) << 0;
      a = (t1 + t2) << 0;
      this.chromeBugWorkAround = true;
    }

    this.h0 = (this.h0 + a) << 0;
    this.h1 = (this.h1 + b) << 0;
    this.h2 = (this.h2 + c) << 0;
    this.h3 = (this.h3 + d) << 0;
    this.h4 = (this.h4 + e) << 0;
    this.h5 = (this.h5 + f) << 0;
    this.h6 = (this.h6 + g) << 0;
    this.h7 = (this.h7 + h) << 0;
  };

  Sha256.prototype.hex = function () {
    this.finalize();

    var h0 = this.h0,
      h1 = this.h1,
      h2 = this.h2,
      h3 = this.h3,
      h4 = this.h4,
      h5 = this.h5,
      h6 = this.h6,
      h7 = this.h7;

    var hex =
      HEX_CHARS[(h0 >>> 28) & 0x0f] +
      HEX_CHARS[(h0 >>> 24) & 0x0f] +
      HEX_CHARS[(h0 >>> 20) & 0x0f] +
      HEX_CHARS[(h0 >>> 16) & 0x0f] +
      HEX_CHARS[(h0 >>> 12) & 0x0f] +
      HEX_CHARS[(h0 >>> 8) & 0x0f] +
      HEX_CHARS[(h0 >>> 4) & 0x0f] +
      HEX_CHARS[h0 & 0x0f] +
      HEX_CHARS[(h1 >>> 28) & 0x0f] +
      HEX_CHARS[(h1 >>> 24) & 0x0f] +
      HEX_CHARS[(h1 >>> 20) & 0x0f] +
      HEX_CHARS[(h1 >>> 16) & 0x0f] +
      HEX_CHARS[(h1 >>> 12) & 0x0f] +
      HEX_CHARS[(h1 >>> 8) & 0x0f] +
      HEX_CHARS[(h1 >>> 4) & 0x0f] +
      HEX_CHARS[h1 & 0x0f] +
      HEX_CHARS[(h2 >>> 28) & 0x0f] +
      HEX_CHARS[(h2 >>> 24) & 0x0f] +
      HEX_CHARS[(h2 >>> 20) & 0x0f] +
      HEX_CHARS[(h2 >>> 16) & 0x0f] +
      HEX_CHARS[(h2 >>> 12) & 0x0f] +
      HEX_CHARS[(h2 >>> 8) & 0x0f] +
      HEX_CHARS[(h2 >>> 4) & 0x0f] +
      HEX_CHARS[h2 & 0x0f] +
      HEX_CHARS[(h3 >>> 28) & 0x0f] +
      HEX_CHARS[(h3 >>> 24) & 0x0f] +
      HEX_CHARS[(h3 >>> 20) & 0x0f] +
      HEX_CHARS[(h3 >>> 16) & 0x0f] +
      HEX_CHARS[(h3 >>> 12) & 0x0f] +
      HEX_CHARS[(h3 >>> 8) & 0x0f] +
      HEX_CHARS[(h3 >>> 4) & 0x0f] +
      HEX_CHARS[h3 & 0x0f] +
      HEX_CHARS[(h4 >>> 28) & 0x0f] +
      HEX_CHARS[(h4 >>> 24) & 0x0f] +
      HEX_CHARS[(h4 >>> 20) & 0x0f] +
      HEX_CHARS[(h4 >>> 16) & 0x0f] +
      HEX_CHARS[(h4 >>> 12) & 0x0f] +
      HEX_CHARS[(h4 >>> 8) & 0x0f] +
      HEX_CHARS[(h4 >>> 4) & 0x0f] +
      HEX_CHARS[h4 & 0x0f] +
      HEX_CHARS[(h5 >>> 28) & 0x0f] +
      HEX_CHARS[(h5 >>> 24) & 0x0f] +
      HEX_CHARS[(h5 >>> 20) & 0x0f] +
      HEX_CHARS[(h5 >>> 16) & 0x0f] +
      HEX_CHARS[(h5 >>> 12) & 0x0f] +
      HEX_CHARS[(h5 >>> 8) & 0x0f] +
      HEX_CHARS[(h5 >>> 4) & 0x0f] +
      HEX_CHARS[h5 & 0x0f] +
      HEX_CHARS[(h6 >>> 28) & 0x0f] +
      HEX_CHARS[(h6 >>> 24) & 0x0f] +
      HEX_CHARS[(h6 >>> 20) & 0x0f] +
      HEX_CHARS[(h6 >>> 16) & 0x0f] +
      HEX_CHARS[(h6 >>> 12) & 0x0f] +
      HEX_CHARS[(h6 >>> 8) & 0x0f] +
      HEX_CHARS[(h6 >>> 4) & 0x0f] +
      HEX_CHARS[h6 & 0x0f];
    if (!this.is224) {
      hex +=
        HEX_CHARS[(h7 >>> 28) & 0x0f] +
        HEX_CHARS[(h7 >>> 24) & 0x0f] +
        HEX_CHARS[(h7 >>> 20) & 0x0f] +
        HEX_CHARS[(h7 >>> 16) & 0x0f] +
        HEX_CHARS[(h7 >>> 12) & 0x0f] +
        HEX_CHARS[(h7 >>> 8) & 0x0f] +
        HEX_CHARS[(h7 >>> 4) & 0x0f] +
        HEX_CHARS[h7 & 0x0f];
    }
    return hex;
  };

  Sha256.prototype.toString = Sha256.prototype.hex;

  Sha256.prototype.digest = function () {
    this.finalize();

    var h0 = this.h0,
      h1 = this.h1,
      h2 = this.h2,
      h3 = this.h3,
      h4 = this.h4,
      h5 = this.h5,
      h6 = this.h6,
      h7 = this.h7;

    var arr = [
      (h0 >>> 24) & 0xff,
      (h0 >>> 16) & 0xff,
      (h0 >>> 8) & 0xff,
      h0 & 0xff,
      (h1 >>> 24) & 0xff,
      (h1 >>> 16) & 0xff,
      (h1 >>> 8) & 0xff,
      h1 & 0xff,
      (h2 >>> 24) & 0xff,
      (h2 >>> 16) & 0xff,
      (h2 >>> 8) & 0xff,
      h2 & 0xff,
      (h3 >>> 24) & 0xff,
      (h3 >>> 16) & 0xff,
      (h3 >>> 8) & 0xff,
      h3 & 0xff,
      (h4 >>> 24) & 0xff,
      (h4 >>> 16) & 0xff,
      (h4 >>> 8) & 0xff,
      h4 & 0xff,
      (h5 >>> 24) & 0xff,
      (h5 >>> 16) & 0xff,
      (h5 >>> 8) & 0xff,
      h5 & 0xff,
      (h6 >>> 24) & 0xff,
      (h6 >>> 16) & 0xff,
      (h6 >>> 8) & 0xff,
      h6 & 0xff,
    ];
    if (!this.is224) {
      arr.push((h7 >>> 24) & 0xff, (h7 >>> 16) & 0xff, (h7 >>> 8) & 0xff, h7 & 0xff);
    }
    return arr;
  };

  Sha256.prototype.array = Sha256.prototype.digest;

  Sha256.prototype.arrayBuffer = function () {
    this.finalize();

    var buffer = new ArrayBuffer(this.is224 ? 28 : 32);
    var dataView = new DataView(buffer);
    dataView.setUint32(0, this.h0);
    dataView.setUint32(4, this.h1);
    dataView.setUint32(8, this.h2);
    dataView.setUint32(12, this.h3);
    dataView.setUint32(16, this.h4);
    dataView.setUint32(20, this.h5);
    dataView.setUint32(24, this.h6);
    if (!this.is224) {
      dataView.setUint32(28, this.h7);
    }
    return buffer;
  };

  function HmacSha256(key, is224, sharedMemory) {
    var i,
      type = typeof key;
    if (type === "string") {
      var bytes = [],
        length = key.length,
        index = 0,
        code;
      for (i = 0; i < length; ++i) {
        code = key.charCodeAt(i);
        if (code < 0x80) {
          bytes[index++] = code;
        } else if (code < 0x800) {
          bytes[index++] = 0xc0 | (code >>> 6);
          bytes[index++] = 0x80 | (code & 0x3f);
        } else if (code < 0xd800 || code >= 0xe000) {
          bytes[index++] = 0xe0 | (code >>> 12);
          bytes[index++] = 0x80 | ((code >>> 6) & 0x3f);
          bytes[index++] = 0x80 | (code & 0x3f);
        } else {
          code = 0x10000 + (((code & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
          bytes[index++] = 0xf0 | (code >>> 18);
          bytes[index++] = 0x80 | ((code >>> 12) & 0x3f);
          bytes[index++] = 0x80 | ((code >>> 6) & 0x3f);
          bytes[index++] = 0x80 | (code & 0x3f);
        }
      }
      key = bytes;
    } else {
      if (type === "object") {
        if (key === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && key.constructor === ArrayBuffer) {
          key = new Uint8Array(key);
        } else if (!Array.isArray(key)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(key)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
    }

    if (key.length > 64) {
      key = new Sha256(is224, true).update(key).array();
    }

    var oKeyPad = [],
      iKeyPad = [];
    for (i = 0; i < 64; ++i) {
      var b = key[i] || 0;
      oKeyPad[i] = 0x5c ^ b;
      iKeyPad[i] = 0x36 ^ b;
    }

    Sha256.call(this, is224, sharedMemory);

    this.update(iKeyPad);
    this.oKeyPad = oKeyPad;
    this.inner = true;
    this.sharedMemory = sharedMemory;
  }
  HmacSha256.prototype = new Sha256();

  HmacSha256.prototype.finalize = function () {
    Sha256.prototype.finalize.call(this);
    if (this.inner) {
      this.inner = false;
      var innerHash = this.array();
      Sha256.call(this, this.is224, this.sharedMemory);
      this.update(this.oKeyPad);
      this.update(innerHash);
      Sha256.prototype.finalize.call(this);
    }
  };

  var exports = createMethod();
  exports.sha256 = exports;
  exports.sha224 = createMethod(true);
  exports.sha256.hmac = createHmacMethod();
  exports.sha224.hmac = createHmacMethod(true);

  if (COMMON_JS) {
    module.exports = exports;
  } else {
    root.sha256 = exports.sha256;
    root.sha224 = exports.sha224;
    if (AMD) {
      define(function () {
        return exports;
      });
    }
  }
})();
