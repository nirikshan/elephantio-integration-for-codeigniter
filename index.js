var app = require('express')();
var http = require('http').createServer(app);


const io = require("socket.io")(http, {
  cors: {
    origin: '*',
  }
});

app.get('/', (req, res) => {
    res.send('<h1>hey</h1>');
});

io.on('connection', function (socket){

  console.log('SocketIO > Connected socket ' + socket.id);

  socket.on('client_s', function (message) {
      console.log('client > ' + JSON.stringify(message));
  });

  socket.on('server_s', function (message) {
    console.log('server > ' + JSON.stringify(message))  ;
    io.emit('client_r', JSON.stringify(message));
  });
  
  socket.on('disconnect', function () {
      console.log('SocketIO > Disconnected socket ' + socket.id);
  });
});


http.listen(3000, () => {
  console.log('listening on *:3000');
});