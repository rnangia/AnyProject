FROM node:latest

RUN npm install webpack -g

ADD ./compose/webpack/prod/start-webpack.sh .
RUN chmod +x /start-webpack.sh

CMD ./start-webpack.sh
