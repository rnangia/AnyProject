FROM node:latest

RUN npm install webpack -g

ADD ./compose/webpack/dev/start-webpack.sh .
RUN chmod +x /start-webpack.sh

CMD ./start-webpack.sh
