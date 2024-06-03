FROM node:18
WORKDIR /app
COPY package*.json ./
RUN npm install -g @angular/cli
RUN npm install
COPY . .
RUN ng analytics off
RUN npm run build 
EXPOSE 4200
CMD ["ng", "serve", "--host", "0.0.0.0", "--port", "4200"]

