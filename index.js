const express = require("express");
const app = express();
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync } = require('child_process');
const http = require('http');
const httpProxy = require('http-proxy');

// 环境变量配置
const UPLOAD_URL = process.env.UPLOAD_URL || '';      // 节点或订阅自动上传地址
const PROJECT_URL = process.env.PROJECT_URL || '';    // 项目访问地址，用于生成订阅链接
const AUTO_ACCESS = process.env.AUTO_ACCESS === 'true'; // 是否自动访问项目URL保持活跃
const FILE_PATH = process.env.FILE_PATH || './tmp';   // 临时文件存储目录路径
const SUB_PATH = process.env.SUB_PATH || 'sub';       // 订阅链接访问路径
const PORT = process.env.SERVER_PORT || process.env.PORT || 7860; // 内部HTTP服务端口
const UUID = process.env.UUID || '4b3e2bfe-bde1-5def-d035-0cb572bbd046'; // Xray用户UUID
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';  // 哪吒监控服务器地址
const NEZHA_PORT = process.env.NEZHA_PORT || '';      // 哪吒v0监控服务器端口（可选）
const NEZHA_KEY = process.env.NEZHA_KEY || '';        // 哪吒监控客户端密钥
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';    // Cloudflare Argo隧道域名
const ARGO_AUTH = process.env.ARGO_AUTH || '';        // Argo隧道认证信息（Token或Json）
const CFIP = process.env.CFIP || 'cdns.doon.eu.org';  // CDN回源IP地址
const CFPORT = process.env.CFPORT || 443;             // CDN回源端口
const NAME = process.env.NAME || '';                  // 节点名称前缀
const MONITOR_KEY = process.env.MONITOR_KEY || '';    // 监控脚本密钥
const MONITOR_SERVER = process.env.MONITOR_SERVER || ''; // 监控服务器标识
const MONITOR_URL = process.env.MONITOR_URL || '';    // 监控上报地址

// 创建运行文件夹
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH, { recursive: true });
  console.log(`${FILE_PATH} is created`);
} else {
  console.log(`${FILE_PATH} already exists`);
}

// 生成随机6位字符文件名
function generateRandomName() {
  const characters = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// 全局文件路径
const npmName = generateRandomName();
const webName = generateRandomName();
const botName = generateRandomName();
const phpName = generateRandomName();
let npmPath = path.join(FILE_PATH, npmName);
let phpPath = path.join(FILE_PATH, phpName);
let webPath = path.join(FILE_PATH, webName);
let botPath = path.join(FILE_PATH, botName);
let monitorPath = path.join(FILE_PATH, 'cf-vps-monitor.sh');
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let configPath = path.join(FILE_PATH, 'config.json');
let nezhaConfigPath = path.join(FILE_PATH, 'config.yaml');
let tunnelJsonPath = path.join(FILE_PATH, 'tunnel.json');
let tunnelYamlPath = path.join(FILE_PATH, 'tunnel.yml');

// 创建HTTP代理
const proxy = httpProxy.createProxyServer();
const proxyServer = http.createServer((req, res) => {
  const path = req.url;
  
  if (path.startsWith('/vless-argo') || 
      path.startsWith('/vmess-argo') || 
      path.startsWith('/trojan-argo') ||
      path === '/vless' || 
      path === '/vmess' || 
      path === '/trojan') {
    proxy.web(req, res, { target: 'http://localhost:3001' });
  } else {
    proxy.web(req, res, { target: `http://localhost:${PORT}` });
  }
});

// WebSocket代理处理
proxyServer.on('upgrade', (req, socket, head) => {
  const path = req.url;
  
  if (path.startsWith('/vless-argo') || 
      path.startsWith('/vmess-argo') || 
      path.startsWith('/trojan-argo')) {
    proxy.ws(req, socket, head, { target: 'http://localhost:3001' });
  } else {
    proxy.ws(req, socket, head, { target: `http://localhost:${PORT}` });
  }
});

// 启动代理服务器
proxyServer.listen(PORT, () => {
  console.log(`Proxy server is running on port:${PORT}!`);
  console.log(`HTTP traffic -> localhost:${PORT}`);
  console.log(`Xray traffic -> localhost:3001`);
});

// 根路由 - 提供外部index.html文件或显示Hello world!
app.get("/", function(req, res) {
  const indexPath = path.join(__dirname, 'index.html');
  
  // 检查index.html文件是否存在
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.send("Hello world!");
  }
});

// 订阅路由
let subscriptionContent = '';
app.get(`/${SUB_PATH}`, (req, res) => {
  const encodedContent = Buffer.from(subscriptionContent).toString('base64');
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.send(encodedContent);
});

// 删除历史节点
function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;
    if (!fs.existsSync(subPath)) return;

    let fileContent;
    try {
      fileContent = fs.readFileSync(subPath, 'utf-8');
    } catch {
      return null;
    }

    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line => 
      /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
    );

    if (nodes.length === 0) return;

    axios.post(`${UPLOAD_URL}/api/delete-nodes`, 
      JSON.stringify({ nodes }),
      { headers: { 'Content-Type': 'application/json' } }
    ).catch((error) => { 
      return null; 
    });
    return null;
  } catch (err) {
    return null;
  }
}

// 清理历史文件
function cleanupOldFiles() {
  try {
    const files = fs.readdirSync(FILE_PATH);
    files.forEach(file => {
      const filePath = path.join(FILE_PATH, file);
      try {
        const stat = fs.statSync(filePath);
        if (stat.isFile()) {
          fs.unlinkSync(filePath);
        }
      } catch (err) {
        // 忽略错误
      }
    });
  } catch (err) {
    // 忽略错误
  }
}

// 生成xr-ay配置文件
async function generateConfig() {
  const config = {
    log: { 
      access: '/dev/null', 
      error: '/dev/null', 
      loglevel: 'none' 
    },
    dns: {
      servers: [
        "https+local://8.8.8.8/dns-query",
        "https+local://1.1.1.1/dns-query",
        "8.8.8.8",
        "1.1.1.1"
      ],
      queryStrategy: "UseIP",
      disableCache: false
    },
    inbounds: [
      { 
        port: 3001,
        protocol: 'vless', 
        settings: { 
          clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], 
          decryption: 'none', 
          fallbacks: [
            { dest: 3002 }, 
            { path: "/vless-argo", dest: 3003 }, 
            { path: "/vmess-argo", dest: 3004 }, 
            { path: "/trojan-argo", dest: 3005 }
          ] 
        }, 
        streamSettings: { network: 'tcp' } 
      },
      { 
        port: 3002, 
        listen: "127.0.0.1", 
        protocol: "vless", 
        settings: { 
          clients: [{ id: UUID }], 
          decryption: "none" 
        }, 
        streamSettings: { 
          network: "tcp", 
          security: "none" 
        } 
      },
      { 
        port: 3003, 
        listen: "127.0.0.1", 
        protocol: "vless", 
        settings: { 
          clients: [{ id: UUID, level: 0 }], 
          decryption: "none" 
        }, 
        streamSettings: { 
          network: "ws", 
          security: "none", 
          wsSettings: { path: "/vless-argo" } 
        }, 
        sniffing: { 
          enabled: true, 
          destOverride: ["http", "tls", "quic"], 
          metadataOnly: false 
        } 
      },
      { 
        port: 3004, 
        listen: "127.0.0.1", 
        protocol: "vmess", 
        settings: { 
          clients: [{ id: UUID, alterId: 0 }] 
        }, 
        streamSettings: { 
          network: "ws", 
          wsSettings: { path: "/vmess-argo" } 
        }, 
        sniffing: { 
          enabled: true, 
          destOverride: ["http", "tls", "quic"], 
          metadataOnly: false 
        } 
      },
      { 
        port: 3005, 
        listen: "127.0.0.1", 
        protocol: "trojan", 
        settings: { 
          clients: [{ password: UUID }] 
        }, 
        streamSettings: { 
          network: "ws", 
          security: "none", 
          wsSettings: { path: "/trojan-argo" } 
        }, 
        sniffing: { 
          enabled: true, 
          destOverride: ["http", "tls", "quic"], 
          metadataOnly: false 
        } 
      }
    ],
    outbounds: [
      {
        protocol: "freedom",
        tag: "direct",
        settings: {
          domainStrategy: "UseIP"
        }
      },
      {
        protocol: "blackhole",
        tag: "block"
      }
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: []
    }
  };
  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));
}

// 判断系统架构
function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  } else {
    return 'amd';
  }
}

// 下载文件
function downloadFile(fileName, fileUrl, callback) {
  const filePath = fileName; 
  
  if (!fs.existsSync(FILE_PATH)) {
    fs.mkdirSync(FILE_PATH, { recursive: true });
  }
  
  const writer = fs.createWriteStream(filePath);

  axios({
    method: 'get',
    url: fileUrl,
    responseType: 'stream',
  })
    .then(response => {
      response.data.pipe(writer);

      writer.on('finish', () => {
        writer.close();
        console.log(`Download ${path.basename(filePath)} successfully`);
        callback(null, filePath);
      });

      writer.on('error', err => {
        fs.unlink(filePath, () => { });
        const errorMessage = `Download ${path.basename(filePath)} failed: ${err.message}`;
        console.error(errorMessage);
        callback(errorMessage);
      });
    })
    .catch(err => {
      const errorMessage = `Download ${path.basename(filePath)} failed: ${err.message}`;
      console.error(errorMessage);
      callback(errorMessage);
    });
}

// 下载监控脚本
async function downloadMonitorScript() {
  return new Promise((resolve, reject) => {
    if (!MONITOR_KEY || !MONITOR_SERVER || !MONITOR_URL) {
      console.log('监控环境变量不完整，跳过监控脚本下载');
      resolve();
      return;
    }

    const monitorURL = 'https://raw.githubusercontent.com/kadidalax/cf-vps-monitor/main/cf-vps-monitor.sh';
    console.log(`从 ${monitorURL} 下载监控脚本`);

    downloadFile(monitorPath, monitorURL, (err) => {
      if (err) {
        console.error('下载监控脚本失败:', err);
        reject(err);
      } else {
        // 设置执行权限
        fs.chmodSync(monitorPath, 0o755);
        console.log('监控脚本下载完成');
        resolve();
      }
    });
  });
}

// 运行监控脚本
async function runMonitorScript() {
  if (!MONITOR_KEY || !MONITOR_SERVER || !MONITOR_URL) {
    console.log('监控环境变量不完整，跳过监控脚本启动');
    return;
  }

  if (!fs.existsSync(monitorPath)) {
    console.error('监控脚本文件不存在');
    return;
  }

  const args = [
    '-i',
    '-k', MONITOR_KEY,
    '-s', MONITOR_SERVER,
    '-u', MONITOR_URL,
  ];

  console.log(`运行监控脚本: ${monitorPath} ${args.join(' ')}`);
  
  try {
    await exec(`nohup ${monitorPath} ${args.join(' ')} >/dev/null 2>&1 &`);
    console.log('监控脚本启动成功');
  } catch (error) {
    console.error(`监控脚本运行错误: ${error}`);
  }
}

// 下载并运行依赖文件
async function downloadFilesAndRun() {  
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);

  if (filesToDownload.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, filePath) => {
        if (err) {
          reject(err);
        } else {
          resolve(filePath);
        }
      });
    });
  });

  try {
    await Promise.all(downloadPromises);
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }

  // 授权文件
  function authorizeFiles(filePaths) {
    const newPermissions = 0o775;
    filePaths.forEach(absoluteFilePath => {
      if (fs.existsSync(absoluteFilePath)) {
        fs.chmod(absoluteFilePath, newPermissions, (err) => {
          if (err) {
            console.error(`Empowerment failed for ${absoluteFilePath}: ${err}`);
          } else {
            console.log(`Empowerment success for ${absoluteFilePath}: ${newPermissions.toString(8)}`);
          }
        });
      }
    });
  }
  const filesToAuthorize = NEZHA_PORT ? [npmPath, webPath, botPath] : [phpPath, webPath, botPath];
  authorizeFiles(filesToAuthorize);

  // 运行ne-zha
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
      const nezhatls = tlsPorts.has(port) ? 'true' : 'false';
      
      const configYaml = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
      
      fs.writeFileSync(nezhaConfigPath, configYaml);
      
      const command = `nohup ${phpPath} -c "${nezhaConfigPath}" >/dev/null 2>&1 &`;
      try {
        await exec(command);
        console.log(`${phpName} is running`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`php running error: ${error}`);
      }
    } else {
      let NEZHA_TLS = '';
      const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
      if (tlsPorts.includes(NEZHA_PORT)) {
        NEZHA_TLS = '--tls';
      }
      const command = `nohup ${npmPath} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
      try {
        await exec(command);
        console.log(`${npmName} is running`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`npm running error: ${error}`);
      }
    }
  } else {
    console.log('NEZHA variable is empty,skip running');
  }

  // 运行xr-ay
  const command1 = `nohup ${webPath} -c ${configPath} >/dev/null 2>&1 &`;
  try {
    await exec(command1);
    console.log(`${webName} is running`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  } catch (error) {
    console.error(`web running error: ${error}`);
  }

  // 运行cloud-fared
  if (fs.existsSync(botPath)) {
    let args;

    if (ARGO_AUTH && ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
    } else if (ARGO_AUTH && ARGO_AUTH.includes('TunnelSecret')) {
      // 确保 YAML 配置已生成
      if (!fs.existsSync(tunnelYamlPath)) {
        console.log('Waiting for tunnel.yml configuration...');
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      args = `tunnel --edge-ip-version auto --config ${tunnelYamlPath} run`;
    } else {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${bootLogPath} --loglevel info --url http://localhost:${PORT}`;
    }

    try {
      await exec(`nohup ${botPath} ${args} >/dev/null 2>&1 &`);
      console.log(`${botName} is running`);
      
      // 等待隧道启动
      console.log('Waiting for tunnel to start...');
      await new Promise((resolve) => setTimeout(resolve, 5000));
      
      // 检查隧道是否成功启动
      if (ARGO_AUTH && ARGO_AUTH.includes('TunnelSecret')) {
        // 对于固定隧道，检查进程是否在运行
        try {
          if (process.platform === 'win32') {
            await exec(`tasklist | findstr ${botName} > nul`);
          } else {
            await exec(`pgrep -f "[${botName.charAt(0)}]${botName.substring(1)}" > /dev/null`);
          }
          console.log('Tunnel is running successfully');
        } catch (error) {
          console.error('Tunnel failed to start');
        }
      }
    } catch (error) {
      console.error(`Error executing command: ${error}`);
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 2000));
}

// 根据系统架构返回对应的url
function getFilesForArchitecture(architecture) {
  let baseFiles;
  if (architecture === 'arm') {
    baseFiles = [
      { fileName: webPath, fileUrl: "https://arm64.ssss.nyc.mn/web" },
      { fileName: botPath, fileUrl: "https://arm64.ssss.nyc.mn/bot" }
    ];
  } else {
    baseFiles = [
      { fileName: webPath, fileUrl: "https://amd64.ssss.nyc.mn/web" },
      { fileName: botPath, fileUrl: "https://amd64.ssss.nyc.mn/bot" }
    ];
  }

  if (NEZHA_SERVER && NEZHA_KEY) {
    if (NEZHA_PORT) {
      const npmUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/agent"
        : "https://amd64.ssss.nyc.mn/agent";
        baseFiles.unshift({ 
          fileName: npmPath, 
          fileUrl: npmUrl 
        });
    } else {
      const phpUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/v1" 
        : "https://amd64.ssss.nyc.mn/v1";
      baseFiles.unshift({ 
        fileName: phpPath, 
        fileUrl: phpUrl
      });
    }
  }

  return baseFiles;
}

// 获取固定隧道json - 确保YAML配置正确生成
function argoType() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) {
    console.log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels");
    return;
  }

  if (ARGO_AUTH.includes('TunnelSecret')) {
    try {
      // 解析JSON获取TunnelID
      const tunnelConfig = JSON.parse(ARGO_AUTH);
      const tunnelId = tunnelConfig.TunnelID;
      
      fs.writeFileSync(tunnelJsonPath, ARGO_AUTH);
      
      const tunnelYaml = `tunnel: ${tunnelId}
credentials-file: ${tunnelJsonPath}
protocol: http2

ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://localhost:${PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
      
      fs.writeFileSync(tunnelYamlPath, tunnelYaml);
      console.log('Tunnel YAML configuration generated successfully');
    } catch (error) {
      console.error('Error generating tunnel configuration:', error);
    }
  } else {
    console.log("ARGO_AUTH mismatch TunnelSecret, use token connect to tunnel");
  }
}

// 获取isp信息
async function getMetaInfo() {
  try {
    const response1 = await axios.get('https://ipapi.co/json/', { timeout: 3000 });
    if (response1.data && response1.data.country_code && response1.data.org) {
      return `${response1.data.country_code}_${response1.data.org}`;
    }
  } catch (error) {
      try {
        // 备用 ip-api.com 获取isp
        const response2 = await axios.get('http://ip-api.com/json/', { timeout: 3000 });
        if (response2.data && response2.data.status === 'success' && response2.data.countryCode && response2.data.org) {
          return `${response2.data.countryCode}_${response2.data.org}`;
        }
      } catch (error) {
        // console.error('Backup API also failed');
      }
  }
  return 'Unknown';
}

// 获取临时隧道domain
async function extractDomains() {
  let argoDomain;

  if (ARGO_AUTH && ARGO_DOMAIN) {
    argoDomain = ARGO_DOMAIN;
    console.log('ARGO_DOMAIN:', argoDomain);
    await generateLinks(argoDomain);
  } else {
    try {
      const fileContent = fs.readFileSync(bootLogPath, 'utf-8');
      const lines = fileContent.split('\n');
      const argoDomains = [];
      lines.forEach((line) => {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) {
          const domain = domainMatch[1];
          argoDomains.push(domain);
        }
      });

      if (argoDomains.length > 0) {
        argoDomain = argoDomains[0];
        console.log('ArgoDomain:', argoDomain);
        await generateLinks(argoDomain);
      } else {
        console.log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
        fs.unlinkSync(bootLogPath);
        async function killBotProcess() {
          try {
            if (process.platform === 'win32') {
              await exec(`taskkill /f /im ${botName}.exe > nul 2>&1`);
            } else {
              await exec(`pkill -f "[${botName.charAt(0)}]${botName.substring(1)}" > /dev/null 2>&1`);
            }
          } catch (error) {
            // 忽略输出
          }
        }
        killBotProcess();
        await new Promise((resolve) => setTimeout(resolve, 3000));
        const args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${bootLogPath} --loglevel info --url http://localhost:${PORT}`;
        try {
          await exec(`nohup ${botPath} ${args} >/dev/null 2>&1 &`);
          console.log(`${botName} is running`);
          await new Promise((resolve) => setTimeout(resolve, 3000));
          await extractDomains();
        } catch (error) {
          console.error(`Error executing command: ${error}`);
        }
      }
    } catch (error) {
      console.error('Error reading boot.log:', error);
    }
  }

  async function generateLinks(argoDomain) {
    // 获取ISP信息
    const ISP = await getMetaInfo();
    const nodeName = NAME ? `${NAME}-${ISP}` : ISP;

    return new Promise((resolve) => {
      setTimeout(() => {
        const VMESS = { v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox'};
        subscriptionContent = `
vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}
  
vmess://${Buffer.from(JSON.stringify(VMESS)).toString('base64')}
  
trojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
    `;
        console.log(Buffer.from(subscriptionContent).toString('base64'));
        fs.writeFileSync(subPath, Buffer.from(subscriptionContent).toString('base64'));
        console.log(`${subPath} saved successfully`);
        uploadNodes();
        resolve(subscriptionContent);
      }, 2000);
    });
  }
}

// 自动上传节点或订阅
async function uploadNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    const subscriptionUrl = `${PROJECT_URL}/${SUB_PATH}`;
    const jsonData = {
      subscription: [subscriptionUrl]
    };
    try {
        const response = await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, jsonData, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response && response.status === 200) {
            console.log('Subscription uploaded successfully');
            return response;
        } else {
          return null;
        }
    } catch (error) {
        if (error.response) {
            if (error.response.status === 400) {
            }
        }
    }
  } else if (UPLOAD_URL) {
      if (!fs.existsSync(listPath)) return;
      const content = fs.readFileSync(listPath, 'utf-8');
      const nodes = content.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));

      if (nodes.length === 0) return;

      const jsonData = JSON.stringify({ nodes });

      try {
          const response = await axios.post(`${UPLOAD_URL}/api/add-nodes`, jsonData, {
              headers: { 'Content-Type': 'application/json' }
          });
          if (response && response.status === 200) {
            console.log('Nodes uploaded successfully');
            return response;
        } else {
            return null;
        }
      } catch (error) {
          return null;
      }
  } else {
      return;
  }
}

// 90s后删除相关文件
function cleanFiles() {
  setTimeout(() => {
    const filesToDelete = [bootLogPath, configPath, webPath, botPath, monitorPath];  
    
    if (NEZHA_PORT) {
      filesToDelete.push(npmPath);
    } else if (NEZHA_SERVER && NEZHA_KEY) {
      filesToDelete.push(phpPath);
    }

    if (process.platform === 'win32') {
      exec(`del /f /q ${filesToDelete.join(' ')} > nul 2>&1`, (error) => {
        console.clear();
        console.log('App is running');
        console.log('Thank you for using this script, enjoy!');
      });
    } else {
      exec(`rm -rf ${filesToDelete.join(' ')} >/dev/null 2>&1`, (error) => {
        console.clear();
        console.log('App is running');
        console.log('Thank you for using this script, enjoy!');
      });
    }
  }, 90000);
}
cleanFiles();

// 自动访问项目URL
async function AddVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) {
    console.log("Skipping adding automatic access task");
    return;
  }

  try {
    const response = await axios.post('https://oooo.serv00.net/add-url', {
      url: PROJECT_URL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log(`automatic access task added successfully`);
    return response;
  } catch (error) {
    console.error(`Add automatic access task faild: ${error.message}`);
    return null;
  }
}

// 启动监控脚本
async function startMonitorScript() {
  try {
    await downloadMonitorScript();
    await runMonitorScript();
  } catch (error) {
    console.error('启动监控脚本失败:', error);
  }
}

// 主运行逻辑
async function startserver() {
  try {
    console.log('Starting server initialization...');
    
    deleteNodes();
    cleanupOldFiles();
    
    argoType();
    
    await generateConfig();
    
    await downloadFilesAndRun();
    
    await extractDomains();
    
    await AddVisitTask();
    
    // 延迟启动监控脚本
    setTimeout(startMonitorScript, 10000);
    
    console.log('Server initialization completed successfully');
  } catch (error) {
    console.error('Error in startserver:', error);
  }
}

app.listen(PORT, () => console.log(`HTTP service is running on internal port:${PORT}!`));

startserver().catch(error => {
  console.error('Unhandled error in startserver:', error);
});
