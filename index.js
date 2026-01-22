const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { spawn, exec } = require('child_process');
const url = require('url');
const httpProxy = require('http-proxy');

// 配置文件
const config = {
  uploadURL: process.env.UPLOAD_URL || '',
  projectURL: process.env.PROJECT_URL || '',
  autoAccess: process.env.AUTO_ACCESS === 'true',
  filePath: process.env.FILE_PATH || './tmp',
  subPath: process.env.SUB_PATH || 'sub',
  port: process.env.SERVER_PORT || process.env.PORT || '7860',
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

// 创建 http-proxy 实例
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  ignorePath: false,
  xfwd: true,
  preserveHeaderKeyCase: true,
  proxyTimeout: 30000,
  timeout: 30000,
});

// 错误处理
proxy.on('error', (err, req, res) => {
  console.error('代理错误:', err.message);
  if (res.writeHead) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Bad Gateway');
  }
});

// 生成随机文件名
function generateRandomName() {
  const letters = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  const bytes = crypto.randomBytes(6);
  for (let i = 0; i < 6; i++) {
    result += letters[bytes[i] % letters.length];
  }
  return result;
}

// 生成文件路径
function generateFilenames() {
  try {
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
  } catch (error) {
    console.error('生成文件名失败:', error.message);
    throw error;
  }
}

// 清理目录
async function cleanup() {
  try {
    if (fsSync.existsSync(config.filePath)) {
      // 使用递归删除，兼容旧版本 Node.js
      const deleteRecursive = async (dir) => {
        const items = await fs.readdir(dir, { withFileTypes: true });
        for (const item of items) {
          const fullPath = path.join(dir, item.name);
          if (item.isDirectory()) {
            await deleteRecursive(fullPath);
          } else {
            await fs.unlink(fullPath);
          }
        }
        await fs.rmdir(dir);
      };
      await deleteRecursive(config.filePath);
    }
  } catch (error) {
    console.log('清理目录失败:', error.message);
  }
  
  try {
    await fs.mkdir(config.filePath, { recursive: true });
    
    if (config.uploadURL) {
      await deleteNodes();
    }
  } catch (error) {
    console.error('创建目录或删除节点失败:', error.message);
  }
}

// 删除节点
async function deleteNodes() {
  if (!config.uploadURL) return;
  
  try {
    // 如果订阅文件存在，读取并删除节点
    if (fsSync.existsSync(files.sub)) {
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
        const urlObj = new URL(config.uploadURL);
        const options = {
          hostname: urlObj.hostname,
          port: urlObj.port || 443,
          path: '/api/delete-nodes',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': data.length.toString(),
          },
          timeout: 10000,
        };
        
        await new Promise((resolve, reject) => {
          const req = https.request(options, (res) => {
            let responseData = '';
            res.on('data', (chunk) => {
              responseData += chunk;
            });
            res.on('end', () => {
              console.log(`删除节点响应: ${res.statusCode}`);
              resolve();
            });
          });
          req.on('error', (err) => {
            console.error('删除节点请求失败:', err.message);
            reject(err);
          });
          req.on('timeout', () => {
            req.destroy();
            reject(new Error('请求超时'));
          });
          req.write(data);
          req.end();
        });
      }
    }
  } catch (error) {
    console.error('删除节点失败:', error.message);
  }
}

// 生成Xray配置
async function generateXrayConfig() {
  try {
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
  } catch (error) {
    console.error('生成Xray配置失败:', error.message);
    throw error;
  }
}

// 下载文件函数
function downloadFile(fileUrl, dest) {
  return new Promise((resolve, reject) => {
    const protocol = fileUrl.startsWith('https') ? https : http;
    const file = fsSync.createWriteStream(dest, { flags: 'wx' });
    
    const request = protocol.get(fileUrl, (response) => {
      if (response.statusCode !== 200) {
        file.close();
        fsSync.unlink(dest, () => {});
        reject(new Error(`下载失败: ${response.statusCode} ${response.statusMessage}`));
        return;
      }
      
      response.pipe(file);
      
      file.on('finish', () => {
        file.close();
        try {
          fsSync.chmodSync(dest, 0o755);
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    
    request.on('error', (err) => {
      file.close();
      fsSync.unlink(dest, () => {});
      reject(err);
    });
    
    file.on('error', (err) => {
      file.close();
      fsSync.unlink(dest, () => {});
      reject(err);
    });
    
    request.setTimeout(30000, () => {
      request.destroy();
      file.close();
      fsSync.unlink(dest, () => {});
      reject(new Error('下载超时'));
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
    downloadFile(baseURL + 'web', files.web)
      .then(() => console.log('下载 web 成功'))
      .catch(err => console.error('下载 web 失败:', err.message))
  );
  
  downloads.push(
    downloadFile(baseURL + 'bot', files.bot)
      .then(() => console.log('下载 bot 成功'))
      .catch(err => console.error('下载 bot 失败:', err.message))
  );
  
  // 哪吒监控文件
  if (config.nezhaServer && config.nezhaKey) {
    if (config.nezhaPort) {
      downloads.push(
        downloadFile(baseURL + 'agent', files.npm)
          .then(() => console.log('下载 agent 成功'))
          .catch(err => console.error('下载 agent 失败:', err.message))
      );
    } else {
      downloads.push(
        downloadFile(baseURL + 'v1', files.php)
          .then(() => console.log('下载 php 成功'))
          .catch(err => console.error('下载 php 失败:', err.message))
      );
    }
  }
  
  try {
    await Promise.allSettled(downloads);
    console.log('所有文件下载完成');
  } catch (error) {
    console.error('下载文件过程中发生错误:', error.message);
  }
}

// 运行哪吒
function runNezha() {
  if (!config.nezhaServer || !config.nezhaKey) {
    console.log('哪吒监控变量为空，跳过运行');
    return;
  }
  
  try {
    if (!config.nezhaPort) {
      // v1版本 - 需要配置文件
      if (!fsSync.existsSync(files.nezhaConfig)) {
        console.error('哪吒配置文件不存在');
        return;
      }
      
      const cmd = spawn(files.php, ['-c', files.nezhaConfig], {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: true
      });
      
      processes.nezha = cmd;
      
      const onData = (data) => console.log(`哪吒: ${data.toString().trim()}`);
      const onError = (data) => console.error(`哪吒错误: ${data.toString().trim()}`);
      
      cmd.stdout.on('data', onData);
      cmd.stderr.on('data', onError);
      
      cmd.on('error', (err) => {
        console.error('启动哪吒失败:', err.message);
      });
      
      cmd.on('close', (code) => {
        console.log(`哪吒进程退出，代码: ${code}`);
        cmd.stdout.removeListener('data', onData);
        cmd.stderr.removeListener('data', onError);
      });
      
      console.log(`${path.basename(files.php)} 运行中，PID: ${cmd.pid}`);
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
      
      const cmd = spawn(files.npm, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: true
      });
      
      processes.nezha = cmd;
      
      const onData = (data) => console.log(`哪吒: ${data.toString().trim()}`);
      const onError = (data) => console.error(`哪吒错误: ${data.toString().trim()}`);
      
      cmd.stdout.on('data', onData);
      cmd.stderr.on('data', onError);
      
      cmd.on('error', (err) => {
        console.error('启动哪吒失败:', err.message);
      });
      
      cmd.on('close', (code) => {
        console.log(`哪吒进程退出，代码: ${code}`);
        cmd.stdout.removeListener('data', onData);
        cmd.stderr.removeListener('data', onError);
      });
      
      console.log(`${path.basename(files.npm)} 运行中，PID: ${cmd.pid}`);
    }
  } catch (error) {
    console.error('运行哪吒失败:', error.message);
  }
}

// 运行Xray
function runXray() {
  try {
    if (!fsSync.existsSync(files.web)) {
      console.error('Xray 可执行文件不存在');
      return;
    }
    
    if (!fsSync.existsSync(files.config)) {
      console.error('Xray 配置文件不存在');
      return;
    }
    
    const cmd = spawn(files.web, ['-c', files.config], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true
    });
    
    processes.xray = cmd;
    
    const onData = (data) => console.log(`Xray: ${data.toString().trim()}`);
    const onError = (data) => console.error(`Xray错误: ${data.toString().trim()}`);
    
    cmd.stdout.on('data', onData);
    cmd.stderr.on('data', onError);
    
    cmd.on('error', (err) => {
      console.error('启动Xray失败:', err.message);
    });
    
    cmd.on('close', (code) => {
      console.log(`Xray进程退出，代码: ${code}`);
      cmd.stdout.removeListener('data', onData);
      cmd.stderr.removeListener('data', onError);
    });
    
    console.log(`${path.basename(files.web)} 运行中，PID: ${cmd.pid}`);
  } catch (error) {
    console.error('运行Xray失败:', error.message);
  }
}

// 生成Argo隧道配置
async function argoType() {
  if (!config.argoAuth || !config.argoDomain) {
    console.log('ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道');
    return;
  }
  
  try {
    // 检查是否为TunnelSecret格式
    if (config.argoAuth.includes('TunnelSecret')) {
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
    service: http://localhost:${config.port}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
      await fs.writeFile(files.tunnelYaml, yamlContent);
      console.log('隧道YAML配置生成成功');
    } else {
      console.log('ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道');
    }
  } catch (error) {
    console.log('解析隧道配置失败:', error.message);
  }
}

// 运行cloudflared
function runCloudflared() {
  try {
    if (!fsSync.existsSync(files.bot)) {
      console.error('cloudflared文件不存在');
      return;
    }
    
    let args;
    
    if (config.argoAuth && config.argoDomain) {
      if (config.argoAuth.includes('TunnelSecret')) {
        if (!fsSync.existsSync(files.tunnelYaml)) {
          console.error('隧道YAML配置文件不存在');
          return;
        }
        args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2',
                '--config', files.tunnelYaml, 'run'];
      } else if (config.argoAuth.length >= 120 && config.argoAuth.length <= 250) {
        args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2',
                'run', '--token', config.argoAuth];
      } else {
        args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2',
                '--logfile', files.bootLog, '--loglevel', 'info',
                '--url', `http://localhost:${config.port}`];
      }
    } else {
      args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2',
              '--logfile', files.bootLog, '--loglevel', 'info',
              '--url', `http://localhost:${config.port}`];
    }
    
    const cmd = spawn(files.bot, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true
    });
    
    processes.cloudflared = cmd;
    
    const onData = (data) => console.log(`cloudflared: ${data.toString().trim()}`);
    const onError = (data) => console.error(`cloudflared错误: ${data.toString().trim()}`);
    
    cmd.stdout.on('data', onData);
    cmd.stderr.on('data', onError);
    
    cmd.on('error', (err) => {
      console.error('启动cloudflared失败:', err.message);
    });
    
    cmd.on('close', (code) => {
      console.log(`cloudflared进程退出，代码: ${code}`);
      cmd.stdout.removeListener('data', onData);
      cmd.stderr.removeListener('data', onError);
    });
    
    console.log(`${path.basename(files.bot)} 运行中，PID: ${cmd.pid}`);
    
    // 延迟检查隧道是否启动成功
    setTimeout(() => {
      if (config.argoAuth && config.argoAuth.includes('TunnelSecret')) {
        if (!cmd.pid) {
          console.log('隧道启动失败');
        } else {
          console.log('隧道运行成功');
        }
      }
    }, 5000);
  } catch (error) {
    console.error('运行cloudflared失败:', error.message);
  }
}

// 获取ISP信息
async function getISP() {
  return new Promise((resolve) => {
    // 第一个API
    const options1 = {
      hostname: 'ipapi.co',
      port: 443,
      path: '/json/',
      method: 'GET',
      timeout: 5000,
      headers: {
        'User-Agent': 'Mozilla/5.0'
      }
    };
    
    const req1 = https.request(options1, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          if (jsonData.country_code && jsonData.org) {
            resolve(`${jsonData.country_code}_${jsonData.org}`.replace(/ /g, '_'));
            return;
          }
        } catch (error) {
          // 解析失败，尝试第二个API
          trySecondAPI(resolve);
        }
      });
    });
    
    req1.on('error', () => {
      trySecondAPI(resolve);
    });
    
    req1.on('timeout', () => {
      req1.destroy();
      trySecondAPI(resolve);
    });
    
    req1.end();
    
    function trySecondAPI(resolve) {
      const options2 = {
        hostname: 'ip-api.com',
        port: 443,
        path: '/json/',
        method: 'GET',
        timeout: 5000,
        headers: {
          'User-Agent': 'Mozilla/5.0'
        }
      };
      
      const req2 = https.request(options2, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            const jsonData = JSON.parse(data);
            if (jsonData.status === 'success' && jsonData.countryCode && jsonData.org) {
              resolve(`${jsonData.countryCode}_${jsonData.org}`.replace(/ /g, '_'));
              return;
            }
          } catch (error) {
            resolve('Unknown');
          }
        });
      });
      
      req2.on('error', () => {
        resolve('Unknown');
      });
      
      req2.on('timeout', () => {
        req2.destroy();
        resolve('Unknown');
      });
      
      req2.end();
    }
  });
}

// 生成订阅链接
async function generateLinks(domain) {
  try {
    console.log(`开始生成订阅链接，域名: ${domain}`);
    
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
    
    // 同时保存到list.txt
    await fs.writeFile(files.list, subscription);
    
    // 立即上传节点
    await uploadNodes();
    
    return subTxt;
  } catch (error) {
    console.error('生成订阅链接失败:', error.message);
    return '';
  }
}

// 提取域名
async function extractDomains() {
  try {
    // 如果配置了固定域名
    if (config.argoAuth && config.argoDomain) {
      console.log(`使用固定域名: ${config.argoDomain}`);
      await generateLinks(config.argoDomain);
      return;
    }
    
    // 从日志文件读取临时域名
    if (!fsSync.existsSync(files.bootLog)) {
      console.log('日志文件不存在，等待cloudflared启动...');
      await new Promise(resolve => setTimeout(resolve, 3000));
      if (!fsSync.existsSync(files.bootLog)) {
        console.log('日志文件仍然不存在，跳过域名提取');
        return;
      }
    }
    
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
    
    console.log('未找到域名，等待重试...');
    // 等待一段时间后重试
    await new Promise(resolve => setTimeout(resolve, 5000));
    await extractDomains();
  } catch (error) {
    console.error('提取域名失败:', error.message);
  }
}

// 上传节点
async function uploadNodes() {
  if (!config.uploadURL) {
    console.log('上传URL为空，跳过上传节点');
    return;
  }
  
  try {
    if (config.projectURL) {
      // 上传订阅
      const subscriptionUrl = `${config.projectURL}/${config.subPath}`;
      const data = JSON.stringify({ subscription: [subscriptionUrl] });
      
      const urlObj = new URL(config.uploadURL);
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: '/api/add-subscriptions',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': data.length.toString(),
        },
        timeout: 10000,
      };
      
      await new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          let responseData = '';
          res.on('data', (chunk) => {
            responseData += chunk;
          });
          res.on('end', () => {
            if (res.statusCode === 200) {
              console.log('订阅上传成功');
            } else {
              console.log('订阅上传失败:', res.statusCode, responseData);
            }
            resolve();
          });
        });
        req.on('error', (err) => {
          console.error('订阅上传请求失败:', err.message);
          reject(err);
        });
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('请求超时'));
        });
        req.write(data);
        req.end();
      });
    } else {
      // 上传节点
      if (!fsSync.existsSync(files.sub)) {
        console.log('订阅文件不存在，跳过上传节点');
        return;
      }
      
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
      
      if (nodes.length === 0) {
        console.log('没有找到节点');
        return;
      }
      
      const jsonData = JSON.stringify({ nodes });
      const urlObj = new URL(config.uploadURL);
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: '/api/add-nodes',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': jsonData.length.toString(),
        },
        timeout: 10000,
      };
      
      await new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          let responseData = '';
          res.on('data', (chunk) => {
            responseData += chunk;
          });
          res.on('end', () => {
            if (res.statusCode === 200) {
              console.log('节点上传成功');
            } else {
              console.log('节点上传失败:', res.statusCode, responseData);
            }
            resolve();
          });
        });
        req.on('error', (err) => {
          console.error('节点上传请求失败:', err.message);
          reject(err);
        });
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('请求超时'));
        });
        req.write(jsonData);
        req.end();
      });
    }
  } catch (error) {
    console.error('上传节点失败:', error.message);
  }
}

// 添加自动访问任务
async function addVisitTask() {
  if (!config.autoAccess || !config.projectURL) {
    console.log('跳过自动访问任务');
    return;
  }
  
  try {
    const data = JSON.stringify({ url: config.projectURL });
    
    const options = {
      hostname: 'oooo.serv00.net',
      port: 443,
      path: '/add-url',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length.toString(),
      },
      timeout: 10000,
    };
    
    await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let responseData = '';
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        res.on('end', () => {
          if (res.statusCode === 200) {
            console.log('自动访问任务添加成功');
          } else {
            console.log('添加自动访问任务失败:', res.statusCode, responseData);
          }
          resolve();
        });
      });
      req.on('error', (err) => {
        console.error('添加自动访问任务请求失败:', err.message);
        reject(err);
      });
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('请求超时'));
      });
      req.write(data);
      req.end();
    });
  } catch (error) {
    console.error('添加自动访问任务失败:', error.message);
  }
}

// 请求处理函数
async function requestHandler(req, res) {
  try {
    const parsedUrl = url.parse(req.url);
    const pathname = parsedUrl.pathname;
    
    // 订阅路径
    if (pathname === `/${config.subPath}` || pathname === `/${config.subPath}/`) {
      if (!subscription) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Subscription not ready yet');
        return;
      }
      
      const encoded = Buffer.from(subscription).toString('base64');
      res.writeHead(200, { 
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-cache'
      });
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
    
    // 检查是否是需要代理到Xray的路径
    const xrayPaths = [
      '/vless-argo',
      '/vmess-argo', 
      '/trojan-argo',
      '/vless',
      '/vmess',
      '/trojan'
    ];
    
    const isXrayPath = xrayPaths.some(xrayPath => pathname.startsWith(xrayPath));
    
    if (isXrayPath) {
      // 代理到Xray (端口3001)
      proxy.web(req, res, { 
        target: `http://localhost:3001`,
        headers: {
          'X-Forwarded-Host': req.headers.host,
          'Host': 'localhost:3001'
        }
      });
    } else {
      // 其他请求返回404
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  } catch (error) {
    console.error('请求处理错误:', error.message);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal Server Error');
  }
}

// 创建HTTP服务器
function createHTTPServer() {
  const server = http.createServer(requestHandler);
  
  server.on('upgrade', (req, socket, head) => {
    const parsedUrl = url.parse(req.url);
    const pathname = parsedUrl.pathname;
    
    const xrayPaths = [
      '/vless-argo',
      '/vmess-argo', 
      '/trojan-argo',
      '/vless',
      '/vmess',
      '/trojan'
    ];
    
    const isXrayPath = xrayPaths.some(xrayPath => pathname.startsWith(xrayPath));
    
    if (isXrayPath) {
      proxy.ws(req, socket, head, { target: `ws://localhost:3001` });
    } else {
      socket.destroy();
    }
  });
  
  server.on('error', (err) => {
    console.error('HTTP服务器错误:', err.message);
    if (err.code === 'EADDRINUSE') {
      console.error(`端口 ${config.port} 已被占用`);
      process.exit(1);
    }
  });
  
  return server;
}

// 主流程
async function startMainProcess() {
  try {
    console.log('开始主流程...');
    
    // 延时启动，确保服务器已启动
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // 生成Argo隧道配置
    await argoType();
    
    // 下载文件
    await downloadFiles();
    
    // 运行哪吒监控（如果配置了）
    runNezha();
    
    // 运行Xray
    runXray();
    
    // 运行Cloudflared
    runCloudflared();
    
    // 等待隧道启动
    console.log('等待隧道启动...');
    await new Promise(resolve => setTimeout(resolve, 10000));
    
    // 提取域名并生成订阅
    await extractDomains();
    
    // 自动访问任务
    await addVisitTask();
    
    console.log('主流程完成');
  } catch (error) {
    console.error('主流程执行失败:', error.message);
  }
}

// 清理文件
async function cleanFiles() {
  try {
    // 延迟90秒清理
    await new Promise(resolve => setTimeout(resolve, 90000));
    
    const filesToDelete = [
      files.bootLog,
      files.config,
      files.web,
      files.bot,
    ];
    
    if (config.nezhaPort) {
      filesToDelete.push(files.npm);
    } else if (config.nezhaServer && config.nezhaKey) {
      filesToDelete.push(files.php);
    }
    
    for (const file of filesToDelete) {
      try {
        if (fsSync.existsSync(file)) {
          await fs.unlink(file);
        }
      } catch (error) {
        console.error(`删除文件失败 ${file}:`, error.message);
      }
    }
    
    console.log('应用正在运行');
    console.log('感谢使用此脚本，享受吧！');
  } catch (error) {
    console.error('清理文件失败:', error.message);
  }
}

// 主函数
async function main() {
  console.log('开始初始化配置...');
  console.log(`最终使用的UUID: ${config.uuid}`);
  
  // 输出监控配置信息
  if (config.monitorKey && config.monitorServer && config.monitorURL) {
    console.log('监控脚本已配置，将自动运行');
    console.log(`监控服务器: ${config.monitorServer}`);
    console.log(`监控URL: ${config.monitorURL}`);
  }
  
  try {
    // 创建目录
    await fs.mkdir(config.filePath, { recursive: true });
    console.log(`目录 ${config.filePath} 已创建或已存在`);
    
    // 生成随机文件名
    generateFilenames();
    
    // 清理历史文件和节点
    await cleanup();
    
    // 生成配置文件
    await generateXrayConfig();
    
    // 创建HTTP服务器
    const server = createHTTPServer();
    
    // 启动HTTP服务器
    server.listen(config.port, () => {
      console.log(`HTTP服务启动在端口: ${config.port}`);
      
      // 启动主流程
      startMainProcess();
      
      // 启动清理文件
      cleanFiles();
    });
    
    // 信号处理
    process.on('SIGINT', () => {
      console.log('收到关闭信号，正在清理...');
      shutdown();
    });
    
    process.on('SIGTERM', () => {
      console.log('收到终止信号，正在清理...');
      shutdown();
    });
    
    process.on('uncaughtException', (err) => {
      console.error('未捕获的异常:', err.message, err.stack);
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      console.error('未处理的Promise拒绝:', reason);
    });
    
  } catch (error) {
    console.error('初始化失败:', error.message);
    process.exit(1);
  }
}

// 清理函数
async function shutdown() {
  console.log('正在停止所有子进程...');
  
  // 停止所有进程
  Object.entries(processes).forEach(([name, proc]) => {
    if (proc && proc.pid) {
      console.log(`停止 ${name} 进程 (PID: ${proc.pid})`);
      try {
        process.kill(proc.pid, 'SIGTERM');
      } catch (error) {
        // 进程可能已经退出
      }
    }
  });
  
  console.log('程序退出');
  process.exit(0);
}

// 启动应用
main().catch((error) => {
  console.error('应用启动失败:', error.message);
  process.exit(1);
});
