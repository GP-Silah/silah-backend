FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npx prisma generate
RUN npm run build


# Create logs folder
RUN mkdir -p logs

RUN chmod +x ./docker/docker-entrypoint.sh

# Add non-root user for safety
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENV PORT=3000
EXPOSE 3000
CMD ["./docker/docker-entrypoint.sh"]