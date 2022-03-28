import dotenv from 'dotenv'
import express from 'express';
import { postgraphile } from 'postgraphile';
import PgOrderByRelatedPlugin from "@graphile-contrib/pg-order-by-related";
import ConnectionFilterPlugin from "postgraphile-plugin-connection-filter";
import ldap from 'ldapjs';
import assert from 'assert';
import expressJwt from 'express-jwt';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import cors from 'cors'
import _ from "lodash";
import { AuthType, createClient } from "webdav";
import fs from 'fs';
import asyncHandler from './asyncHandler.js';
import busboy from 'busboy';
import https from 'https'

// load env file
dotenv.config();
console.log("DATABASE_URL: "+process.env.DATABASE_URL)

let roles=["v_visitatore"];

// webdav
const webdavClient = createClient(process.env.WEBDAV_URL, {
  // authType: AuthType.Digest,
  username: process.env.WEBDAV_USERNAME,
  password: process.env.WEBDAV_PASSWORD
});

function generateAccessToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
}

// ldap
function ldapSearch(client,base,filter=null,attributes=[]) {
  return new Promise(async (resolve,reject) => {
    const opts = {
      filter,
      scope: 'sub',
      attributes
    };
    
    let output=[];

    client.search(base, opts, (err, res) => {
      if (err) {
        reject({
          reason: "err",
          status: err
        });
        return;
      }
      
      res.on('searchRequest', (searchRequest) => {
        //console.log('searchRequest: ', searchRequest.messageID);
      });
      res.on('searchEntry', (entry) => {
        //console.log('entry: ' + JSON.stringify(entry.object));
        output.push(entry.object);
      });
      res.on('searchReference', (referral) => {
        //console.log('referral: ' + referral.uris.join());
      });
      res.on('error', (err) => {
        //console.error('error: ' + err.message);
        reject({
          reason: "err",
          err
        });
      });
      res.on('end', (result) => {
        //console.log('status: ' + result.status);
        if (result.status==0)
          resolve(output);
        else
          reject({
            reason: "end",
            status: result.status
          });
      });
    });
  });
}

function aa(email,password,prefix) {
  return new Promise(async (resolve,reject) => {
    let res;

    const client = ldap.createClient({
      url: process.env.LDAP_URL
    });
    
    client.on('error', (err) => {
      // handle connection error
      reject({reason: "LDAP connection error",err});
    });

    let field="mail";
    if  (!email.includes("@"))
      field="uid";

    try {
      res=await ldapSearch(client,process.env.BASE_SEARCH,field+'='+email);
    }
    catch (err) {
      reject({ reason: "search", err });
      return;
    }

    if (res.length==0) {
      reject({ reason: "No user" });
      return;
    }

    let dn=res[0].dn;

    client.bind(dn, password, (err) => {
      // handle bind error
      if (err)
        reject({reason: "LDAP bind error", err});
    });

    try {
      res=await ldapSearch(client,process.env.BASE_SEARCH,field+'='+email);
    }
    catch (err) {
      reject({ reason: "search", err });
      return;
    }

    if (!res[0].isMemberOf) {
      reject({ reason: "No isMemberOf" });
      return;
    }

    if (Array.isArray(res[0].isMemberOf)) {
      let output = res[0].isMemberOf.filter(function (isMemberOf) {
        return isMemberOf.startsWith(prefix);
      });
      output=output.map(function (isMemberOf) {
        return isMemberOf.substring(prefix.length);
      });

      console.log(output);
      resolve(output);
    }
    else {
      let output=res[0].isMemberOf.substring(prefix.length);
      resolve(output);
    }
  });
}


// express
const app = express();


async (req, res, next) => {
  try {
    return await fn(req, res, next)
  } catch (err) {
    next(err)
  }
}

app.use(cors())

app.use(express.json())

app.use(morgan('combined'));

app.post('/login',
  asyncHandler(async function(req, res) {
    if (!req.body) return res.status(400).json({ message: "Missing body" });
    if (!req.body.email) return res.status(400).json({ message: "No email supplied" });
    if (!req.body.password) return res.status(400).json({ message: "No password supplied" });

    let role=await aa(req.body.email,req.body.password,process.env.AA_PREFIX);
    const token = generateAccessToken({
      email: req.body.email,
      password: req.body.password,
      role: role.replace(":","_")
    });
    res.json(token);
  })
);

app.use(expressJwt({secret: process.env.JWT_SECRET, algorithms: ['HS256']}));

app.use((req, res, next) => {
  if (roles.length && !roles.includes(req.user.role)) {
    // user's role is not authorized
    return res.status(401).json({ message: "Unauthorized Access" });
  }
  next();
});


app.get('/alfresco/:filename',
  asyncHandler(async function(req, res, next) {
    res.attachment(req.params.filename);
    const rstream=webdavClient.createReadStream("/"+req.params.filename);
    rstream.on('error', function (err) {
      next(err);
    });
    rstream.pipe(res);
  })
);
app.put('/alfresco/:filename',
  asyncHandler(async function(req, res, next) {
    const bb = busboy({ headers: req.headers });
    bb.on('file', (fieldname, file, info) => {
      console.log(`Upload of '${info.filename}' started`);

      // Create a write stream of the new file
      const wstream = webdavClient.createWriteStream("/"+req.params.filename);

      // On finish of the upload
      file.on('close', () => {
        console.log(`Upload of '${info.filename}' finished`);
        res.status(200).send("OK");
      });
      wstream.on('error', function (err) {
        next(err);
      });
      // Pipe it trough
      file.pipe(wstream);
    });
    req.pipe(bb);
  })
);
app.delete('/alfresco/:filename',
  asyncHandler(async function(req, res, next) {
    let file=await webdavClient.deleteFile("/"+req.params.filename);
    res.status(200).send("OK");
  })
);


app.get('/userdata',
  asyncHandler(function(req, res) {
    // res.sendStatus(200).json({ message: "Ottimo!" });
    let user=_.cloneDeep(req.user);
    delete user.password;
    res.status(200).json(user);
  })
);

app.use(postgraphile(
    process.env.DATABASE_URL || "postgres://user:pass@host:5432/dbname",
    "public",
    {
      graphileBuildOptions: {
        connectionFilterRelations: true
      },
      watchPg: true,
      graphiql: true,
      enhanceGraphiql: true,
      graphqlRoute: "/graphql",
      pgSettings: async req => ({
        'role': req.user.role,
      }),
      appendPlugins: [PgOrderByRelatedPlugin,ConnectionFilterPlugin]
    }
));

app.use(function(err, req, res, next) {
  console.error(err);
  res.status(500).send(err);
});

var privateKey  = fs.readFileSync(process.env.KEY_FILE, 'utf8');
var certificate = fs.readFileSync(process.env.CERT_FILE, 'utf8');
var credentials = {key: privateKey, cert: certificate};

var httpsServer = https.createServer(credentials, app);
httpsServer.listen(process.env.PORT || 8443, () => {
  console.log('Server running on port %d', process.env.PORT);
});
