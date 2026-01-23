const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const http = require('http');
const { spawn, exec } = require('child_process');
const crypto = require('crypto');
const axios = require('axios');
const httpProxy = require('http-proxy');

// 配置结构
const config = {
  uploadURL: process.env.UPLOAD_URL || '',
  projectURL: process.env.PROJECT_URL || '',
  autoAccess: process.env.AUTO_ACCESS === 'true',
  filePath: process.env.FILE_PATH || './tmp',
  subPath: process.env.SUB_PATH || 'sub',
  port: process.env.SERVER_PORT || process.env.PORT || '3000',
  externalPort: process.env.EXTERNAL_PORT || '7860',
  uuid: process.env.UUID || '4b3e2bfe-bde1-5def-d035-0cb572bbd046',
  nezhaServer: process.env.NEZHA_SERVER || '',
  nezhaPort: process.env.NEZHA_PORT || '',
  nezhaKey: process.env.NEZHA_KEY || '',
  argoDomain: process.env.ARGO_DOMAIN || '',
  argoAuth: process.env.ARGO_AUTH || '',
  cfip: process.env.CFIP || 'cdns.doon.eu.org',
  cfport: process.env.CFPORT || '443',
  name: process.env.NAME || '',
  monitorKey: process.env.MONITOR_KEY || '',
  monitorServer: process.env.MONITOR_SERVER || '',
  monitorURL: process.env.MONITOR_URL || ''
};

// 全局变量
const files = {};
let subscription = '';
let monitorProcess = null;
const app = express();

// 生成随机文件名
function generateRandomName(length = 6) {
  const letters = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  const randomBytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    result += letters[randomBytes[i] % letters.length];
  }
  return result;
}

// 初始化文件路径
function initFilePaths() {
  files.npm = path.join(config.filePath, generateRandomName());
  files.web = path.join(config.filePath, generateRandomName());
  files.bot = path.join(config.filePath, generateRandomName());
  files.php = path.join(config.filePath, generateRandomName());
  files.monitor = path.join(config.filePath, 'cf-vps-monitor.sh');
  files.sub = path.join(config.filePath, 'sub.txt');
  files.list = path.join(config.filePath, 'list.txt');
  files.bootLog = path.join(config.filePath, 'boot.log');
  files.config = path.join(config.filePath, 'config.json');
  files.nezhaConfig = path.join(config.filePath, 'config.yaml');
  files.tunnelJson = path.join(config.filePath, 'tunnel.json');
  files.tunnelYaml = path.join(config.filePath, 'tunnel.yml');
}

// 清理目录
async function cleanup() {
  try {
    await fs.rm(config.filePath, { recursive: true, force: true });
  } catch (err) {
    // 忽略错误
  }
  
  await fs.mkdir(config.filePath, { recursive: true });
  console.log(`目录 ${config.filePath} 已创建或已存在`);
  
  await deleteNodes();
}

// 删除节点
async function deleteNodes() {
  if (!config.uploadURL) return;

  try {
    const subData = await fs.readFile(files.sub, 'utf8');
    const decoded = Buffer.from(subData, 'base64').toString('utf8');
    const lines = decoded.split('\n');
    const nodes = lines.filter(line => 
      line.includes('vless://') ||
      line.includes('vmess://') ||
      line.includes('trojan://') ||
      line.includes('hysteria2://') ||
      line.includes('tuic://')
    );

    if (nodes.length === 0) return;

    await axios.post(`${config.uploadURL}/api/delete-nodes`, 
      { nodes },
      { timeout: 10000 }
    );
  } catch (err) {
    // 忽略错误
  }
}

// 生成Xray配置
async function generateXrayConfig() {
  const xrayConfig = {
    log: {
      access: "/dev/null",
      error: "/dev/null",
      loglevel: "none"
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
        protocol: "vless",
        settings: {
          clients: [{
            id: config.uuid,
            flow: "xtls-rprx-vision"
          }],
          decryption: "none",
          fallbacks: [
            { dest: 3002 },
            { path: "/vless-argo", dest: 3003 },
            { path: "/vmess-argo", dest: 3004 },
            { path: "/trojan-argo", dest: 3005 }
          ]
        },
        streamSettings: {
          network: "tcp"
        }
      },
      {
        port: 3002,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: {
          clients: [{ id: config.uuid }],
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
          clients: [{ id: config.uuid, level: 0 }],
          decryption: "none"
        },
        streamSettings: {
          network: "ws",
          security: "none",
          wsSettings: {
            path: "/vless-argo"
          }
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
          clients: [{ id: config.uuid, alterId: 0 }]
        },
        streamSettings: {
          network: "ws",
          wsSettings: {
            path: "/vmess-argo"
          }
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
          clients: [{ password: config.uuid }]
        },
        streamSettings: {
          network: "ws",
          security: "none",
          wsSettings: {
            path: "/trojan-argo"
          }
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
        tag: "block",
        settings: {}
      }
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: []
    }
  };

  await fs.writeFile(files.config, JSON.stringify(xrayConfig, null, 2));
  console.log("Xray配置文件生成完成");
}

// 创建HTTP代理服务器（使用你提供的路由方式）
function createProxyServer() {
  const proxy = httpProxy.createProxyServer();
  const proxyServer = http.createServer((req, res) => {
    const reqPath = req.url;
    
    if (reqPath.startsWith('/vless-argo') || 
        reqPath.startsWith('/vmess-argo') || 
        reqPath.startsWith('/trojan-argo') ||
        reqPath === '/vless' || 
        reqPath === '/vmess' || 
        reqPath === '/trojan') {
      proxy.web(req, res, { target: 'http://localhost:3001' });
    } else {
      proxy.web(req, res, { target: `http://localhost:${config.port}` });
    }
  });

  // WebSocket代理处理
  proxyServer.on('upgrade', (req, socket, head) => {
    const reqPath = req.url;
    
    if (reqPath.startsWith('/vless-argo') || 
        reqPath.startsWith('/vmess-argo') || 
        reqPath.startsWith('/trojan-argo')) {
      proxy.ws(req, socket, head, { target: 'http://localhost:3001' });
    } else {
      proxy.ws(req, socket, head, { target: `http://localhost:${config.port}` });
    }
  });

  return proxyServer;
}

// 设置Express路由
function setupRoutes() {
  // 根路由 - 提供外部index.html文件或显示Hello world!
  app.get("/", function(req, res) {
    const indexPath = path.join(__dirname, 'index.html');
    
    // 检查index.html文件是否存在
    if (fsSync.existsSync(indexPath)) {
      res.sendFile(indexPath);
    } else {
      res.send("Hello world!");
    }
  });

  // 订阅路由（动态添加，在生成订阅后添加）
}

// 启动HTTP服务器
function startHTTPServer() {
  // 设置路由
  setupRoutes();
  
  // 创建代理服务器
  const proxyServer = createProxyServer();
  
  // 启动代理服务器（外部端口）
  proxyServer.listen(config.externalPort, () => {
    console.log(`外部代理服务启动在端口: ${config.externalPort}!`);
    console.log(`HTTP traffic -> localhost:${config.port}`);
    console.log(`Xray traffic -> localhost:3001`);
  });

  // 启动内部HTTP服务
  const internalServer = http.createServer(app);
  internalServer.listen(config.port, () => {
    console.log(`内部HTTP服务启动在端口: ${config.port}!`);
  });
}

// 下载监控脚本
async function downloadMonitorScript() {
  if (!config.monitorKey || !config.monitorServer || !config.monitorURL) {
    console.log("监控环境变量不完整，跳过监控脚本启动");
    return false;
  }

  const monitorURL = "https://raw.githubusercontent.com/kadidalax/cf-vps-monitor/main/cf-vps-monitor.sh";
  
  console.log(`从 ${monitorURL} 下载监控脚本`);
  
  try {
    const response = await axios.get(monitorURL, { responseType: 'stream' });
    const writer = fsSync.createWriteStream(files.monitor);
    
    response.data.pipe(writer);
    
    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        fsSync.chmodSync(files.monitor, 0o755);
        console.log("监控脚本下载完成");
        resolve(true);
      });
      writer.on('error', reject);
    });
  } catch (err) {
    console.error(`下载监控脚本失败: ${err}`);
    return false;
  }
}

// 运行监控脚本
function runMonitorScript() {
  if (!config.monitorKey || !config.monitorServer || !config.monitorURL) {
    return;
  }

  const args = [
    '-i',
    '-k', config.monitorKey,
    '-s', config.monitorServer,
    '-u', config.monitorURL
  ];

  console.log(`运行监控脚本: ${files.monitor} ${args.join(' ')}`);

  const process = spawn(files.monitor, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true
  });

  monitorProcess = process;

  process.stdout.on('data', (data) => {
    console.log(`监控脚本输出: ${data.toString().trim()}`);
  });

  process.stderr.on('data', (data) => {
    console.error(`监控脚本错误: ${data.toString().trim()}`);
  });

  process.on('close', (code) => {
    console.log(`监控脚本退出，代码: ${code}`);
    if (code !== 0) {
      console.log("将在30秒后重启监控脚本...");
      setTimeout(() => {
        runMonitorScript();
      }, 30000);
    }
  });
}

// 启动监控脚本
async function startMonitorScript() {
  setTimeout(async () => {
    const downloaded = await downloadMonitorScript();
    if (downloaded) {
      runMonitorScript();
    }
  }, 10000);
}

// Argo隧道配置
async function argoType() {
  if (!config.argoAuth || !config.argoDomain) {
    console.log("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道");
    return;
  }

  if (config.argoAuth.includes('TunnelSecret')) {
    try {
      const tunnelConfig = JSON.parse(config.argoAuth);
      const tunnelID = tunnelConfig.TunnelID;
      
      await fs.writeFile(files.tunnelJson, config.argoAuth);
      
      const yamlContent = `tunnel: ${tunnelID}
credentials-file: ${files.tunnelJson}
protocol: http2

ingress:
  - hostname: ${config.argoDomain}
    service: http://localhost:${config.externalPort}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
      
      await fs.writeFile(files.tunnelYaml, yamlContent);
      console.log("隧道YAML配置生成成功");
    } catch (err) {
      console.error(`解析隧道配置失败: ${err}`);
    }
  } else {
    console.log("ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道");
  }
}

// 获取系统架构
function getArchitecture() {
  const arch = process.arch;
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return "arm";
  }
  return "amd";
}

// 下载文件
async function downloadFile(filePath, url) {
  return new Promise(async (resolve, reject) => {
    try {
      const response = await axios.get(url, { responseType: 'stream' });
      const writer = fsSync.createWriteStream(filePath);
      
      response.data.pipe(writer);
      
      writer.on('finish', () => {
        fsSync.chmodSync(filePath, 0o755);
        resolve();
      });
      
      writer.on('error', reject);
    } catch (err) {
      reject(err);
    }
  });
}

// 下载所有文件
async function downloadFiles() {
  const arch = getArchitecture();
  const baseURL = arch === "arm" 
    ? "https://arm64.ssss.nyc.mn/" 
    : "https://amd64.ssss.nyc.mn/";

  const filesToDownload = [
    { name: "web", path: files.web, url: baseURL + "web" },
    { name: "bot", path: files.bot, url: baseURL + "bot" }
  ];

  if (config.nezhaServer && config.nezhaKey) {
    if (config.nezhaPort) {
      filesToDownload.unshift({
        name: "agent",
        path: files.npm,
        url: baseURL + "agent"
      });
    } else {
      filesToDownload.unshift({
        name: "php",
        path: files.php,
        url: baseURL + "v1"
      });
    }
  }

  const promises = filesToDownload.map(async (file) => {
    try {
      await downloadFile(file.path, file.url);
      console.log(`下载 ${file.name} 成功`);
    } catch (err) {
      console.error(`下载 ${file.name} 失败: ${err}`);
    }
  });

  await Promise.all(promises);
  console.log("所有文件下载完成");
}

// 运行哪吒监控
function runNezha() {
  if (!config.nezhaServer || !config.nezhaKey) {
    console.log("哪吒监控变量为空，跳过运行");
    return;
  }

  if (!config.nezhaPort) {
    // v1版本
    const portMatch = config.nezhaServer.match(/:(\d+)$/);
    const port = portMatch ? portMatch[1] : "443";
    
    const tlsPorts = new Set(["443", "8443", "2096", "2087", "2083", "2053"]);
    const nezhatls = tlsPorts.has(port) ? "true" : "false";
    
    const yamlContent = `client_secret: ${config.nezhaKey}
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
server: ${config.nezhaServer}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${config.uuid}`;

    fsSync.writeFileSync(files.nezhaConfig, yamlContent);
    
    const process = spawn(files.php, ["-c", files.nezhaConfig], {
      stdio: 'ignore',
      detached: true
    });
    
    process.unref();
    console.log(`${path.basename(files.php)} 运行中`);
  } else {
    // v0版本
    const args = [
      "-s", `${config.nezhaServer}:${config.nezhaPort}`,
      "-p", config.nezhaKey
    ];

    const tlsPorts = new Set(["443", "8443", "2096", "2087", "2083", "2053"]);
    if (tlsPorts.has(config.nezhaPort)) {
      args.push("--tls");
    }

    args.push("--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs");

    const process = spawn(files.npm, args, {
      stdio: 'ignore',
      detached: true
    });
    
    process.unref();
    console.log(`${path.basename(files.npm)} 运行中`);
  }
}

// 运行Xray
function runXray() {
  const process = spawn(files.web, ["-c", files.config], {
    stdio: 'ignore',
    detached: true
  });
  
  process.unref();
  console.log(`${path.basename(files.web)} 运行中`);
}

// 运行Cloudflared
function runCloudflared() {
  if (!fsSync.existsSync(files.bot)) {
    console.log("cloudflared文件不存在");
    return;
  }

  const args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"];

  if (config.argoAuth && config.argoDomain) {
    if (config.argoAuth.includes('TunnelSecret')) {
      args.push("--config", files.tunnelYaml, "run");
    } else if (config.argoAuth.length >= 120 && config.argoAuth.length <= 250) {
      args.push("run", "--token", config.argoAuth);
    } else {
      args.push("--logfile", files.bootLog, "--loglevel", "info",
                "--url", `http://localhost:${config.externalPort}`);
    }
  } else {
    args.push("--logfile", files.bootLog, "--loglevel", "info",
              "--url", `http://localhost:${config.externalPort}`);
  }

  const process = spawn(files.bot, args, {
    stdio: 'ignore',
    detached: true
  });
  
  process.unref();
  console.log(`${path.basename(files.bot)} 运行中`);
}

// 获取ISP信息
async function getISP() {
  const client = axios.create({ timeout: 3000 });

  try {
    const response = await client.get("https://ipapi.co/json/");
    const data = response.data;
    if (data.country_code && data.org) {
      return `${data.country_code}_${data.org}`.replace(/ /g, "_");
    }
  } catch (err) {
    // 忽略错误
  }

  try {
    const response = await client.get("http://ip-api.com/json/");
    const data = response.data;
    if (data.status === "success" && data.countryCode && data.org) {
      return `${data.countryCode}_${data.org}`.replace(/ /g, "_");
    }
  } catch (err) {
    // 忽略错误
  }

  return "Unknown";
}

// 提取域名并生成链接
async function extractDomains() {
  if (config.argoAuth && config.argoDomain) {
    console.log(`使用固定域名: ${config.argoDomain}`);
    await generateLinks(config.argoDomain);
    return;
  }

  // 从日志文件读取临时域名
  try {
    const data = await fs.readFile(files.bootLog, 'utf8');
    const lines = data.split('\n');
    
    for (const line of lines) {
      if (line.includes('trycloudflare.com')) {
        const urlMatch = line.match(/https?:\/\/[^\s]+trycloudflare\.com[^\s]*/);
        if (urlMatch) {
          const url = urlMatch[0];
          const argoDomain = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
          console.log(`找到临时域名: ${argoDomain}`);
          await generateLinks(argoDomain);
          return;
        }
      }
    }
  } catch (err) {
    console.error(`读取日志文件失败: ${err}`);
  }

  console.log("未找到域名，尝试重启cloudflared");
  await restartCloudflared();
}

// 重启Cloudflared
async function restartCloudflared() {
  // 停止现有进程
  exec(`pkill -f ${path.basename(files.bot)}`, (err) => {
    if (err) console.error(`停止cloudflared失败: ${err}`);
  });
  
  // 删除日志文件
  try {
    await fs.unlink(files.bootLog);
  } catch (err) {
    // 忽略错误
  }

  await new Promise(resolve => setTimeout(resolve, 3000));

  // 重新启动
  const args = [
    "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
    "--logfile", files.bootLog, "--loglevel", "info",
    "--url", `http://localhost:${config.externalPort}`
  ];

  const process = spawn(files.bot, args, {
    stdio: 'ignore',
    detached: true
  });
  
  process.unref();

  await new Promise(resolve => setTimeout(resolve, 3000));
  await extractDomains();
}

// 生成订阅链接
async function generateLinks(domain) {
  const isp = await getISP();
  const nodeName = config.name ? `${config.name}-${isp}` : isp;

  // 生成VMESS配置
  const vmessConfig = {
    v: "2",
    ps: nodeName,
    add: config.cfip,
    port: config.cfport,
    id: config.uuid,
    aid: "0",
    scy: "none",
    net: "ws",
    type: "none",
    host: domain,
    path: "/vmess-argo?ed=2560",
    tls: "tls",
    sni: domain,
    fp: "firefox"
  };

  const vmessJSON = JSON.stringify(vmessConfig);
  const vmessBase64 = Buffer.from(vmessJSON).toString('base64');

  // 生成订阅内容
  subscription = `
vless://${config.uuid}@${config.cfip}:${config.cfport}?encryption=none&security=tls&sni=${domain}&fp=firefox&type=ws&host=${domain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}

vmess://${vmessBase64}

trojan://${config.uuid}@${config.cfip}:${config.cfport}?security=tls&sni=${domain}&fp=firefox&type=ws&host=${domain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
`;

  // 保存到文件
  const encoded = Buffer.from(subscription).toString('base64');
  await fs.writeFile(files.sub, encoded);
  console.log(`订阅文件已保存: ${files.sub}`);
  console.log(`订阅内容:\n${encoded}`);

  // 动态添加订阅路由
  app.get(`/${config.subPath}`, (req, res) => {
    const encodedContent = Buffer.from(subscription).toString('base64');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(encodedContent);
  });
}

// 上传节点
async function uploadNodes() {
  if (!config.uploadURL) return;

  if (config.projectURL) {
    // 上传订阅
    const subscriptionUrl = `${config.projectURL}/${config.subPath}`;
    const jsonData = {
      subscription: [subscriptionUrl]
    };

    try {
      await axios.post(`${config.uploadURL}/api/add-subscriptions`, jsonData, {
        timeout: 10000
      });
      console.log("订阅上传成功");
    } catch (err) {
      console.error(`订阅上传失败: ${err}`);
    }
  } else {
    // 上传节点
    try {
      const data = await fs.readFile(files.list, 'utf8');
      const lines = data.split('\n');
      const nodes = lines.filter(line => 
        line.includes('vless://') ||
        line.includes('vmess://') ||
        line.includes('trojan://') ||
        line.includes('hysteria2://') ||
        line.includes('tuic://')
      );

      if (nodes.length === 0) return;

      await axios.post(`${config.uploadURL}/api/add-nodes`, 
        { nodes },
        { timeout: 10000 }
      );
      console.log("节点上传成功");
    } catch (err) {
      // 忽略错误
    }
  }
}

// 自动访问任务
async function addVisitTask() {
  if (!config.autoAccess || !config.projectURL) {
    console.log("跳过自动访问任务");
    return;
  }

  try {
    await axios.post("https://oooo.serv00.net/add-url", 
      { url: config.projectURL },
      { timeout: 10000 }
    );
    console.log("自动访问任务添加成功");
  } catch (err) {
    console.error(`添加自动访问任务失败: ${err}`);
  }
}

// 清理历史文件
function cleanupOldFiles() {
  try {
    const fileList = fsSync.readdirSync(config.filePath);
    fileList.forEach(file => {
      const filePath = path.join(config.filePath, file);
      try {
        const stat = fsSync.statSync(filePath);
        if (stat.isFile()) {
          fsSync.unlinkSync(filePath);
        }
      } catch (err) {
        // 忽略错误
      }
    });
  } catch (err) {
    // 忽略错误
  }
}

// 清理文件
function cleanFiles() {
  setTimeout(() => {
    const filesToDelete = [
      files.bootLog,
      files.config,
      files.web,
      files.bot,
      files.monitor
    ];

    if (config.nezhaPort) {
      filesToDelete.push(files.npm);
    } else if (config.nezhaServer && config.nezhaKey) {
      filesToDelete.push(files.php);
    }

    if (process.platform === 'win32') {
      exec(`del /f /q ${filesToDelete.join(' ')} > nul 2>&1`, (error) => {
        console.clear();
        console.log('应用正在运行');
        console.log('感谢使用此脚本，享受吧！');
      });
    } else {
      exec(`rm -rf ${filesToDelete.join(' ')} >/dev/null 2>&1`, (error) => {
        console.clear();
        console.log('应用正在运行');
        console.log('感谢使用此脚本，享受吧！');
      });
    }
  }, 90000);
}

// 主流程
async function startMainProcess() {
  try {
    console.log('开始服务器初始化...');
    
    deleteNodes();
    cleanupOldFiles();
    
    await argoType();
    await generateXrayConfig();
    await downloadFiles();
    
    runNezha();
    runXray();
    runCloudflared();
    
    await new Promise(resolve => setTimeout(resolve, 5000));
    await extractDomains();
    await uploadNodes();
    await addVisitTask();
    
    console.log('服务器初始化完成');
  } catch (error) {
    console.error('启动过程中出错:', error);
  }
}

// 初始化
async function init() {
  console.log("配置初始化完成");
  console.log(`最终使用的UUID: ${config.uuid}`);

  if (config.monitorKey && config.monitorServer && config.monitorURL) {
    console.log("监控脚本已配置，将自动运行");
    console.log(`监控服务器: ${config.monitorServer}`);
    console.log(`监控URL: ${config.monitorURL}`);
  }

  initFilePaths();
  startHTTPServer();
  startMonitorScript();
  startMainProcess();
  cleanFiles();
}

// 启动程序
init().catch(err => {
  console.error("启动失败:", err);
  process.exit(1);
});

// 信号处理
process.on('SIGINT', () => {
  console.log("收到关闭信号，正在清理...");
  
  if (monitorProcess) {
    console.log("停止监控脚本...");
    monitorProcess.kill();
  }
  
  console.log("程序退出");
  process.exit(0);
});
