# 使用官方Node.js镜像
FROM node:18-alpine AS builder

# 安装必要的构建工具
RUN apk add --no-cache git curl wget bash

# 设置工作目录
WORKDIR /app

# 复制package.json文件
COPY package*.json ./

# 安装依赖（生产环境依赖）
RUN npm ci --only=production

# 复制应用代码
COPY . .

# 创建必要的目录
RUN mkdir -p /app/tmp

# 设置权限
RUN chmod -R 755 /app

# 最终运行时镜像
FROM node:18-alpine

# 安装必要的运行时工具
RUN apk add --no-cache ca-certificates bash curl wget \
    && apk add --no-cache --virtual .build-deps python3 make g++ \
    && rm -rf /var/cache/apk/*

# 创建非root用户
RUN addgroup -g 1001 -S nodejs \
    && adduser -S nodejs -u 1001

# 设置工作目录
WORKDIR /app

# 从构建阶段复制node_modules和应用代码
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/*.js ./
COPY --from=builder /app/index.html ./

# 创建必要的目录并设置权限
RUN mkdir -p /app/tmp \
    && chown -R nodejs:nodejs /app \
    && chmod -R 755 /app

# 切换到非root用户
USER nodejs

# 暴露端口
EXPOSE 3000 7860

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# 运行应用
CMD ["node", "index.js"]
