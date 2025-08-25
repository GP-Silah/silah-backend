FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npx prisma generate
RUN npm run build

RUN chmod +x ./docker/docker-entrypoint.sh

ENV PORT=3000
EXPOSE 3000
CMD ["./docker/docker-entrypoint.sh"]