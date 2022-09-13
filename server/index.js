const http = require('http');

const app = require('./app');

const server = http.createServer(app);

const PORT = process.env.PORT || 8080;

server.listen(PORT, () => {
  console.log('listening on port ' + PORT);
});
