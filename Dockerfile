FROM node:10.1.0-alpine
RUN mkdir /app
WORKDIR /app
COPY ./package*.json ./
RUN yarn
COPY . .
EXPOSE 3100
CMD ["yarn", "start"]
