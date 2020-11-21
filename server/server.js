const express = require('express');
const ldap = require('ldapjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const _ = require('lodash');
const app = express();
const port = process.env.PORT || 8080;

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

var client;

const authenticateDN = (username, password) => {
  client = ldap.createClient({url: 'ldap://127.0.0.1:10389'});

  client.bind(username, password, function(err) {
    if (err) console.log('error in connection', err);
    else console.log('connected to ldap');
  });
}

var getUser = ({userName, password}) => {
  return new Promise((resolve, reject) => {
    try {
      var opts = {
        filter: `(&(cn=${userName})(sn=${password}))`,
        scope: 'sub',
        attributes: ['sn', 'cn']
      };
    
      client.search('ou=users,dc=partition1,dc=com', opts, (err, res, req) => {
        if (err) reject(err);
        else {
          res.on('searchEntry', (entry) => resolve(entry.object));
        }  
      });
    }
    catch (error) {
      reject(err);
      next(error);
    }
  });
}

app.post('/api/vulnerable/bad/ldap', async(request, respond, next) => {
  var {userName, password} = request.body;

  getUser({userName, password}).then(result => respond.send(result));
});

app.post('/api/vulnerable/good/ldap', async(request, respond, next) => {
  var {userName, password} = request.body;

  if (/[*]/g.test(userName) || /[*]/g.test(password)) respond.sendStatus(500);
  else getUser({userName, password}).then(result => respond.send(result));
});

app.listen(port, () => console.log(`server is running on port ${port}`));
authenticateDN('uid=admin,ou=system', 'secret');
