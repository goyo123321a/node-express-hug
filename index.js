const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { spawn, exec, execSync } = require('child_process');
const { promisify } = require('util');
const util = require('util');
const url = require('url');
const querystring = require('querystring');

// 配置文件
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
  monitorURL: process.env.MONITOR_URL || '',
};

// 文件路径映射
const files = {};
let subscription = '';
let processes = {
  nezha: null,
  xray: null,
  cloudflared: null,
  monitor: null,
};

// 生成随机文件名
function generateRandomName() {
  const letters = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += letters[crypto.randomInt(0, letters.length)];
  }
  return result;
}

// 生成文件路径
function generateFilenames() {
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
  
  console.log('文件名生成完成');
}

// 清理目录
async function cleanup() {
  try {
    await fs.rm(config.filePath, { recursive: true, force: true });
  } catch (error) {
    console.log('清理目录失败:', error.message);
  }
  
  await fs.mkdir(config.filePath, { recursive: true });
  
  if (config.uploadURL) {
    await deleteNodes();
  }
}

// 删除节点
async function deleteNodes() {
  try {
    const subContent = await fs.readFile(files.sub, 'utf8');
    const decoded = Buffer.from(subContent, 'base64').toString();
    const lines = decoded.split('\n');
    const nodes = lines.filter(line => 
      line.includes('vless://') ||
      line.includes('vmess://') ||
      line.includes('trojan://') ||
      line.includes('hysteria2://') ||
      line.includes('tuic://')
    );
    
    if (nodes.length > 0) {
      const data = JSON.stringify({ nodes });
      const options = {
        hostname: new URL(config.uploadURL).hostname,
        port: new URL(config.uploadURL).port || 443,
        path: '/api/delete-nodes',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': data.length,
        },
      };
      
      await new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          resolve();
        });
        req.on('error', reject);
        req.write(data);
        req.end();
      });
    }
  } catch (error) {
    // 文件不存在或无节点可删除，忽略错误
  }
}

// 生成Xray配置
async function generateXrayConfig() {
  const xrayConfig = {
    log: {
      access: "/dev/null",
      error: "/dev/null",
      loglevel: "none",
    },
    dns: {
      servers: [
        "https+local://8.8.8.8/dns-query",
        "https+local://1.1.1.1/dns-query",
        "8.8.8.8",
        "1.1.1.1",
      ],
      queryStrategy: "UseIP",
      disableCache: false,
    },
    inbounds: [
      {
        port: 3001,
        protocol: "vless",
        settings: {
          clients: [
            {
              id: config.uuid,
              flow: "xtls-rprx-vision",
            },
          ],
          decryption: "none",
          fallbacks: [
            { dest: 3002 },
            { path: "/vless-argo", dest: 3003 },
            { path: "/vmess-argo", dest: 3004 },
            { path: "/trojan-argo", dest: 3005 },
          ],
        },
        streamSettings: {
          network: "tcp",
        },
      },
      {
        port: 3002,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: {
          clients: [{ id: config.uuid }],
          decryption: "none",
        },
        streamSettings: {
          network: "tcp",
          security: "none",
        },
      },
      {
        port: 3003,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: {
          clients: [{ id: config.uuid, level: 0 }],
          decryption: "none",
        },
        streamSettings: {
          network: "ws",
          security: "none",
          wsSettings: {
            path: "/vless-argo",
          },
        },
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls", "quic"],
          metadataOnly: false,
        },
      },
      {
        port: 3004,
        listen: "127.0.0.1",
        protocol: "vmess",
        settings: {
          clients: [{ id: config.uuid, alterId: 0 }],
        },
        streamSettings: {
          network: "ws",
          wsSettings: {
            path: "/vmess-argo",
          },
        },
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls", "quic"],
          metadataOnly: false,
        },
      },
      {
        port: 3005,
        listen: "127.0.0.1",
        protocol: "trojan",
        settings: {
          clients: [{ password: config.uuid }],
        },
        streamSettings: {
          network: "ws",
          security: "none",
          wsSettings: {
            path: "/trojan-argo",
          },
        },
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls", "quic"],
          metadataOnly: false,
        },
      },
    ],
    outbounds: [
      {
        protocol: "freedom",
        tag: "direct",
        settings: {
          domainStrategy: "UseIP",
        },
      },
      {
        protocol: "blackhole",
        tag: "block",
        settings: {},
      },
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [],
    },
  };
  
  await fs.writeFile(files.config, JSON.stringify(xrayConfig, null, 2));
  console.log('Xray配置文件生成完成');
}

// 下载文件函数
function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const protocol = url.startsWith('https') ? https : http;
    const file = fsSync.createWriteStream(dest);
    
    protocol.get(url, (response) => {
      if (response.statusCode !== 200) {
        reject(new Error(`Failed to get '${url}' (${response.statusCode})`));
        return;
      }
      
      response.pipe(file);
      file.on('finish', () => {
        file.close();
        fsSync.chmodSync(dest, 0o755);
        resolve();
      });
    }).on('error', (err) => {
      fsSync.unlink(dest, () => {});
      reject(err);
    });
  });
}

// 获取系统架构
function getArchitecture() {
  const arch = process.arch;
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  }
  return 'amd';
}

// 下载所需文件
async function downloadFiles() {
  const arch = getArchitecture();
  const baseURL = arch === 'arm' ? 'https://arm64.ssss.nyc.mn/' : 'https://amd64.ssss.nyc.mn/';
  
  const downloads = [];
  
  // 基础文件
  downloads.push(
    downloadFile(baseURL + 'web', files.web).then(() => console.log('下载 web 成功')),
    downloadFile(baseURL + 'bot', files.bot).then(() => console.log('下载 bot 成功'))
  );
  
  // 哪吒监控文件
  if (config.nezhaServer && config.nezhaKey) {
    if (config.nezhaPort) {
      downloads.push(
        downloadFile(baseURL + 'agent', files.npm).then(() => console.log('下载 agent 成功'))
      );
    } else {
      downloads.push(
        downloadFile(baseURL + 'v1', files.php).then(() => console.log('下载 php 成功'))
      );
    }
  }
  
  await Promise.allSettled(downloads);
  console.log('所有文件下载完成');
}

// 生成哪吒配置
async function nezhaType() {
  if (!config.nezhaServer || !config.nezhaKey) return;
  
  let nezhaConfig = '';
  
  if (!config.nezhaPort) {
    // v1版本
    const urlObj = new URL(config.nezhaServer.startsWith('http') ? config.nezhaServer : `https://${config.nezhaServer}`);
    const port = urlObj.port || '443';
    
    const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
    const nezhatls = tlsPorts.includes(port) ? 'true' : 'false';
    
    nezhaConfig = `client_secret: ${config.nezhaKey}
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
    
    await fs.writeFile(files.nezhaConfig, nezhaConfig);
    console.log('哪吒配置文件生成完成');
  }
}

// 运行哪吒
function runNezha() {
  if (!config.nezhaServer || !config.nezhaKey) {
    console.log('哪吒监控变量为空，跳过运行');
    return;
  }
  
  if (!config.nezhaPort) {
    // v1版本
    const cmd = spawn(files.php, ['-c', files.nezhaConfig]);
    processes.nezha = cmd;
    
    cmd.stdout.on('data', (data) => console.log(`哪吒: ${data}`));
    cmd.stderr.on('data', (data) => console.error(`哪吒错误: ${data}`));
    
    console.log(`${path.basename(files.php)} 运行中`);
  } else {
    // v0版本
    const args = [
      '-s', `${config.nezhaServer}:${config.nezhaPort}`,
      '-p', config.nezhaKey,
    ];
    
    const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
    if (tlsPorts.includes(config.nezhaPort)) {
      args.push('--tls');
    }
    
    args.push('--disable-auto-update', '--report-delay', '4', '--skip-conn', '--skip-procs');
    
    const cmd = spawn(files.npm, args);
    processes.nezha = cmd;
    
    cmd.stdout.on('data', (data) => console.log(`哪吒: ${data}`));
    cmd.stderr.on('data', (data) => console.error(`哪吒错误: ${data}`));
    
    console.log(`${path.basename(files.npm)} 运行中`);
  }
}

// 运行Xray
function runXray() {
  const cmd = spawn(files.web, ['-c', files.config]);
  processes.xray = cmd;
  
  cmd.stdout.on('data', (data) => console.log(`Xray: ${data}`));
  cmd.stderr.on('data', (data) => console.error(`Xray错误: ${data}`));
  
  console.log(`${path.basename(files.web)} 运行中`);
}

// 生成Argo隧道配置
async function argoType() {
  if (!config.argoAuth || !config.argoDomain) {
    console.log('ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道');
    return;
  }
  
  // 检查是否为TunnelSecret格式
  if (config.argoAuth.includes('TunnelSecret')) {
    try {
      const tunnelConfig = JSON.parse(config.argoAuth);
      const tunnelID = tunnelConfig.TunnelID;
      
      // 写入tunnel.json
      await fs.writeFile(files.tunnelJson, config.argoAuth);
      
      // 生成tunnel.yml
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
      console.log('隧道YAML配置生成成功');
    } catch (error) {
      console.log('解析隧道配置失败:', error.message);
    }
  } else {
    console.log('ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道');
  }
}

// 运行cloudflared
function runCloudflared() {
  if (!fsSync.existsSync(files.bot)) {
    console.log('cloudflared文件不存在');
    return;
  }
  
  const args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2'];
  
  if (config.argoAuth && config.argoDomain) {
    if (config.argoAuth.includes('TunnelSecret')) {
      args.push('--config', files.tunnelYaml, 'run');
    } else if (config.argoAuth.length >= 120 && config.argoAuth.length <= 250) {
      args.push('run', '--token', config.argoAuth);
    } else {
      args.push('--logfile', files.bootLog, '--loglevel', 'info',
                '--url', `http://localhost:${config.externalPort}`);
    }
  } else {
    args.push('--logfile', files.bootLog, '--loglevel', 'info',
              '--url', `http://localhost:${config.externalPort}`);
  }
  
  const cmd = spawn(files.bot, args);
  processes.cloudflared = cmd;
  
  cmd.stdout.on('data', (data) => console.log(`cloudflared: ${data}`));
  cmd.stderr.on('data', (data) => console.error(`cloudflared错误: ${data}`));
  
  console.log(`${path.basename(files.bot)} 运行中`);
  
  // 检查隧道是否启动成功
  setTimeout(async () => {
    if (config.argoAuth && config.argoAuth.includes('TunnelSecret')) {
      if (!cmd.pid) {
        console.log('隧道启动失败');
      } else {
        console.log('隧道运行成功');
      }
    }
  }, 5000);
}

// 获取ISP信息
async function getISP() {
  try {
    const response = await fetch('https://ipapi.co/json/');
    const data = await response.json();
    if (data.country_code && data.org) {
      return `${data.country_code}_${data.org}`.replace(/ /g, '_');
    }
  } catch (error) {
    // 备用API
    try {
      const response = await fetch('http://ip-api.com/json/');
      const data = await response.json();
      if (data.status === 'success' && data.countryCode && data.org) {
        return `${data.countryCode}_${data.org}`.replace(/ /g, '_');
      }
    } catch (error2) {
      // 忽略错误
    }
  }
  return 'Unknown';
}

// 生成订阅链接
async function generateLinks(domain) {
  const isp = await getISP();
  let nodeName = config.name;
  
  if (nodeName) {
    nodeName = `${nodeName}-${isp}`;
  } else {
    nodeName = isp;
  }
  
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
    fp: "firefox",
  };
  
  const vmessBase64 = Buffer.from(JSON.stringify(vmessConfig)).toString('base64');
  
  // 生成订阅内容
  const subTxt = `
vless://${config.uuid}@${config.cfip}:${config.cfport}?encryption=none&security=tls&sni=${domain}&fp=firefox&type=ws&host=${domain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}

vmess://${vmessBase64}

trojan://${config.uuid}@${config.cfip}:${config.cfport}?security=tls&sni=${domain}&fp=firefox&type=ws&host=${domain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
`;
  
  subscription = subTxt;
  
  // 保存到文件
  const encoded = Buffer.from(subTxt).toString('base64');
  await fs.writeFile(files.sub, encoded);
  console.log(`订阅文件已保存: ${files.sub}`);
  console.log(`订阅内容:\n${encoded}`);
}

// 提取域名
async function extractDomains() {
  // 如果配置了固定域名
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
        const match = line.match(/https?:\/\/[^\s]+trycloudflare\.com[^\s]*/);
        if (match) {
          const url = match[0];
          const domain = url.replace(/https?:\/\//, '').replace(/\/$/, '');
          console.log(`找到临时域名: ${domain}`);
          await generateLinks(domain);
          return;
        }
      }
    }
    
    console.log('未找到域名，尝试重启cloudflared');
    await restartCloudflared();
  } catch (error) {
    console.log('读取日志文件失败:', error.message);
    await restartCloudflared();
  }
}

// 重启cloudflared
async function restartCloudflared() {
  if (processes.cloudflared) {
    processes.cloudflared.kill();
  }
  
  try {
    await fs.unlink(files.bootLog);
  } catch (error) {
    // 忽略错误
  }
  
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  runCloudflared();
  
  await new Promise(resolve => setTimeout(resolve, 3000));
  await extractDomains();
}

// 上传节点
async function uploadNodes() {
  if (!config.uploadURL) return;
  
  if (config.projectURL) {
    // 上传订阅
    const subscriptionUrl = `${config.projectURL}/${config.subPath}`;
    const data = JSON.stringify({ subscription: [subscriptionUrl] });
    
    try {
      const urlObj = new URL(config.uploadURL);
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: '/api/add-subscriptions',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': data.length,
        },
      };
      
      await new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          if (res.statusCode === 200) {
            console.log('订阅上传成功');
          } else {
            console.log('订阅上传失败');
          }
          resolve();
        });
        req.on('error', reject);
        req.write(data);
        req.end();
      });
    } catch (error) {
      console.log('订阅上传失败:', error.message);
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
      
      if (nodes.length > 0) {
        const jsonData = JSON.stringify({ nodes });
        const urlObj = new URL(config.uploadURL);
        const options = {
          hostname: urlObj.hostname,
          port: urlObj.port || 443,
          path: '/api/add-nodes',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': jsonData.length,
          },
        };
        
        await new Promise((resolve, reject) => {
          const req = https.request(options, (res) => {
            if (res.statusCode === 200) {
              console.log('节点上传成功');
            }
            resolve();
          });
          req.on('error', reject);
          req.write(jsonData);
          req.end();
        });
      }
    } catch (error) {
      // 文件不存在或无节点，忽略
    }
  }
}

// 添加自动访问任务
async function addVisitTask() {
  if (!config.autoAccess || !config.projectURL) {
    console.log('跳过自动访问任务');
    return;
  }
  
  const data = JSON.stringify({ url: config.projectURL });
  
  try {
    const options = {
      hostname: 'oooo.serv00.net',
      port: 443,
      path: '/add-url',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length,
      },
    };
    
    await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        if (res.statusCode === 200) {
          console.log('自动访问任务添加成功');
        } else {
          console.log('添加自动访问任务失败');
        }
        resolve();
      });
      req.on('error', reject);
      req.write(data);
      req.end();
    });
  } catch (error) {
    console.log('添加自动访问任务失败:', error.message);
  }
}

// 下载监控脚本
async function downloadMonitorScript() {
  const monitorURL = 'https://raw.githubusercontent.com/kadidalax/cf-vps-monitor/main/cf-vps-monitor.sh';
  console.log(`从 ${monitorURL} 下载监控脚本`);
  
  await downloadFile(monitorURL, files.monitor);
  console.log('监控脚本下载完成');
}

// 运行监控脚本
function runMonitorScript() {
  if (!config.monitorKey || !config.monitorServer || !config.monitorURL) {
    console.log('监控环境变量不完整，跳过监控脚本启动');
    return;
  }
  
  const args = [
    '-i',
    '-k', config.monitorKey,
    '-s', config.monitorServer,
    '-u', config.monitorURL,
  ];
  
  console.log(`运行监控脚本: ${files.monitor} ${args.join(' ')}`);
  
  const cmd = spawn(files.monitor, args);
  processes.monitor = cmd;
  
  cmd.stdout.on('data', (data) => console.log(`监控: ${data}`));
  cmd.stderr.on('data', (data) => console.error(`监控错误: ${data}`));
  
  console.log('监控脚本启动成功');
  
  // 如果进程退出，尝试重启
  cmd.on('close', (code) => {
    console.log(`监控脚本已退出，代码 ${code}，将在30秒后重启...`);
    setTimeout(runMonitorScript, 30000);
  });
}

// 启动监控脚本（延迟）
async function startMonitorScript() {
  if (!config.monitorKey || !config.monitorServer || !config.monitorURL) {
    console.log('监控环境变量不完整，跳过监控脚本启动');
    return;
  }
  
  // 等待其他服务启动
  await new Promise(resolve => setTimeout(resolve, 10000));
  
  console.log('开始下载并运行监控脚本...');
  
  try {
    await downloadMonitorScript();
    await fs.chmod(files.monitor, 0o755);
    runMonitorScript();
  } catch (error) {
    console.log('监控脚本启动失败:', error.message);
  }
}

// 清理文件
async function cleanFiles() {
  const filesToDelete = [
    files.bootLog,
    files.config,
    files.web,
    files.bot,
    files.monitor,
  ];
  
  if (config.nezhaPort) {
    filesToDelete.push(files.npm);
  } else if (config.nezhaServer && config.nezhaKey) {
    filesToDelete.push(files.php);
  }
  
  for (const file of filesToDelete) {
    try {
      await fs.unlink(file);
    } catch (error) {
      // 忽略错误
    }
  }
  
  console.log('应用正在运行');
  console.log('感谢使用此脚本，享受吧！');
}

// HTTP服务器
function createHTTPServer() {
  const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url);
    const pathname = parsedUrl.pathname;
    
    // 订阅路径
    if (pathname === `/${config.subPath}` || pathname === `/${config.subPath}/`) {
      const encoded = Buffer.from(subscription).toString('base64');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(encoded);
      return;
    }
    
    // 根路径
    if (pathname === '/') {
      try {
        if (fsSync.existsSync('index.html')) {
          const data = await fs.readFile('index.html');
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(data);
        } else if (fsSync.existsSync('/app/index.html')) {
          const data = await fs.readFile('/app/index.html');
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(data);
        } else {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('Hello world!');
        }
      } catch (error) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello world!');
      }
      return;
    }
    
    // 代理逻辑
    let targetHost = 'localhost';
    let targetPort = config.port;
    
    if (pathname.startsWith('/vless-argo') ||
        pathname.startsWith('/vmess-argo') ||
        pathname.startsWith('/trojan-argo') ||
        pathname === '/vless' ||
        pathname === '/vmess' ||
        pathname === '/trojan') {
      targetPort = '3001';
    }
    
    const proxyOptions = {
      hostname: targetHost,
      port: targetPort,
      path: req.url,
      method: req.method,
      headers: {
        ...req.headers,
        host: `${targetHost}:${targetPort}`,
        'x-forwarded-host': req.headers.host,
      },
    };
    
    const proxyReq = http.request(proxyOptions, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });
    
    proxyReq.on('error', (err) => {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Bad Gateway');
    });
    
    req.pipe(proxyReq);
  });
  
  // 启动外部端口
  server.listen(config.externalPort, () => {
    console.log(`外部代理服务启动在端口: ${config.externalPort}`);
  });
  
  // 启动内部服务
  server.listen(config.port, () => {
    console.log(`内部HTTP服务启动在端口: ${config.port}`);
  });
}

// 主流程
async function startMainProcess() {
  // 延时启动
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // 生成Argo隧道配置
  await argoType();
  
  // 下载文件
  await downloadFiles();
  
  // 生成哪吒配置
  await nezhaType();
  
  // 运行哪吒监控
  runNezha();
  
  // 运行Xray
  runXray();
  
  // 运行Cloudflared
  runCloudflared();
  
  // 等待隧道启动
  await new Promise(resolve => setTimeout(resolve, 5000));
  
  // 提取域名并生成订阅
  await extractDomains();
  
  // 上传节点
  await uploadNodes();
  
  // 自动访问任务
  await addVisitTask();
  
  // 清理文件（90秒后）
  setTimeout(cleanFiles, 90000);
}

// 主函数
async function main() {
  console.log('开始初始化配置...');
  
  // 创建目录
  await fs.mkdir(config.filePath, { recursive: true });
  console.log(`目录 ${config.filePath} 已创建或已存在`);
  
  // 生成随机文件名
  generateFilenames();
  
  // 清理历史文件和节点
  await cleanup();
  
  // 生成配置文件
  await generateXrayConfig();
  
  // 启动HTTP服务器
  createHTTPServer();
  
  // 启动监控脚本
  startMonitorScript();
  
  // 主流程
  startMainProcess();
  
  // 信号处理
  process.on('SIGINT', () => {
    console.log('收到关闭信号，正在清理...');
    
    // 停止所有进程
    Object.values(processes).forEach(proc => {
      if (proc) proc.kill();
    });
    
    console.log('程序退出');
    process.exit(0);
  });
  
  process.on('SIGTERM', () => {
    console.log('收到终止信号，正在清理...');
    
    Object.values(processes).forEach(proc => {
      if (proc) proc.kill();
    });
    
    console.log('程序退出');
    process.exit(0);
  });
}

// 启动应用
main().catch(console.error);
