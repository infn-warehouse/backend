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
import multer from 'multer';
import fs from 'fs';
import asyncHandler from './asyncHandler.js';

// load env file
dotenv.config();
console.log("DATABASE_URL: "+process.env.DATABASE_URL)

let roles=["v_visitatore"];

//multer
const upload = multer({ dest: 'uploads/' })

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

function aa(email,password,dn,prefix) {
  return new Promise(async (resolve,reject) => {
    let res;

    const client = ldap.createClient({
      url: process.env.LDAP_URL
    });
    
    client.on('error', (err) => {
      // handle connection error
      reject({reason: "LDAP connection error",err});
    });

    try {
      res=await ldapSearch(client,process.env.BASE_SEARCH,'mail='+email);
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
      res=await ldapSearch(client,process.env.BASE_SEARCH,'mail='+email);
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

    let dn,role;
    try {
      //dn=await getDn(req.body.email);
      role=await aa(req.body.email,req.body.password,dn,process.env.AA_PREFIX);
    }
    catch (err) {
      return res.status(500).json(err);
    }
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



app.get('/scans/:filename',
  asyncHandler(async function(req, res) {
    let file=await webdavClient.getFileContents("/"+req.params.filename);
    res.status(200).send(file);
  })
);
app.post('/scans/:filename',upload.single('data'),
  asyncHandler(async function(req, res) {
    let data = fs.readFileSync(req.file.path);
    let file=await webdavClient.putFileContents("/"+req.params.filename,data);
    res.status(200).send("OK");
  })
);
app.delete('/scans/:filename',
  asyncHandler(async function(req, res) {
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

app.listen(process.env.PORT || 3000, () => {
  console.log('Server running on port %d', process.env.PORT);
});
