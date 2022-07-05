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
import { makeQueryRunner } from "./QueryRunner.cjs";
import meter from 'stream-meter';
import bodyParser from 'body-parser'
import {
  AtomicMutationsPlugin,
  getMutationAtomicityContext,
} from 'postgraphile-plugin-atomic-mutations';

// load env file
dotenv.config();
console.log("DATABASE_URL: "+process.env.DATABASE_URL)

// graphile
const runner = await makeQueryRunner(
  process.env.DATABASE_URL || "postgres://user:pass@host:5432/dbname",
  "public",
  {
    pgSettings: async req => ({
      'role': req.user.role,
    }),
  }
);

// webdav
function createWebdavClient(username,password) {
  return createClient(process.env.WEBDAV_URL, {
    // authType: AuthType.Digest,
    username: username,
    password: password
  });
}

function generateAccessToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
}

function removeCredentials(url) {
  let split1 = url.split("//");
  let protocol=split1[0];
  split1.splice(0,1);
  let join1=split1.join("//");

  let split2=join1.split("@");
  split2.splice(0,1);
  let join2=split2.join("@");

  return protocol+"//"+join2;
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
          searchError: "ERR",
          err
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
          searchError: "ERROR_EVENT",
          err
        });
      });
      res.on('end', (result) => {
        //console.log('status: ' + result.status);
        if (result.status==0)
          resolve(output);
        else
          reject({
            searchError: "END",
            status: result.status
          });
      });
    });
  });
}

function aa(username,password,prefix) {
  return new Promise(async (resolve,reject) => {
    let res;

    const client = ldap.createClient({
      url: process.env.LDAP_URL
    });
    
    client.on('error', (err) => {
      console.log("LDAP general error");
    });
    client.on('connectError', (err) => {
      // handle connection error
      reject({aaError: "CONN_ERROR",err});
    });
    client.on('connect', async () => {
      // let field="mail";
      // if  (!username.includes("@"))
      //   field="uid";
      let field="uid";
  
      try {
        res=await ldapSearch(client,process.env.BASE_SEARCH,field+'='+username);
      }
      catch (err) {
        reject({ aaError: "SEARCH_ERROR", err });
        return;
      }
  
      if (res.length==0) {
        reject({ aaError: "NO_USER" });
        return;
      }
  
      let dn=res[0].dn;
  
      client.bind(dn, password, async (err) => {
        // handle bind error
        if (err)
          reject({aaError: "BIND_ERROR", err});
        else {
          try {
            res=await ldapSearch(client,process.env.BASE_SEARCH,field+'='+username);
          }
          catch (err) {
            reject({ aaError: "SEARCH_ERROR", err });
            return;
          }
          
          let role;
      
          if (!res[0].isMemberOf) {
            reject({ aaError: "NO_ATTRIBUTE" });
            return;
          }
      
          if (Array.isArray(res[0].isMemberOf)) {
            let temp = res[0].isMemberOf.filter(function (isMemberOf) {
              return isMemberOf.startsWith(prefix);
            });
            if (temp.length==0) {
              reject({ aaError: "NO_ROLE" });
              return;
            }
            role=temp[0].substring(prefix.length);
          }
          else {
            role=res[0].isMemberOf.substring(prefix.length);
          }
      
          resolve({
            role: "v_visitatore", // TEMP: for test purposes
            uid: res[0].uid,
            email: res[0].mail
          });
        }
      });
    });
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

app.use(cors());

app.use(express.json());

app.use(bodyParser.text());

app.use(morgan('combined'));

app.post('/login',
  asyncHandler(async function(req, res) {
    if (!req.body) return res.status(400).json({ message: "Missing body" });
    if (!req.body.username) return res.status(400).json({ message: "No username supplied" });
    if (!req.body.password) return res.status(400).json({ message: "No password supplied" });

    let data=await aa(req.body.username,req.body.password,process.env.AA_PREFIX);
    const token = generateAccessToken({
      email: data.email,
      uid: data.uid,
      password: req.body.password,
      role: data.role.replace(":","_").replace("|","_")
    });
    res.json(token);
  })
);

app.use(expressJwt({secret: process.env.JWT_SECRET, algorithms: ['HS256']}));

// app.use((req, res, next) => {
//   if (roles.length && !roles.includes(req.user.role)) {
//     // user's role is not authorized
//     return res.status(401).json({ message: "Unauthorized Access" });
//   }
//   next();
// });


app.get('/alfresco/:filename',
  asyncHandler(async function(req, res, next) {
    let webdavClient=createWebdavClient(req.user.uid,req.user.password);

    const stat = await webdavClient.stat("/"+req.params.filename);
    res.attachment(req.params.filename);
    res.setHeader('Content-Length', stat.size);

    const rstream=webdavClient.createReadStream("/"+req.params.filename);
    rstream.on('error', function (err) {
      next(err);
    });
    rstream.pipe(res);
  })
);
app.get('/alfresco/:filename/link',
  asyncHandler(async function(req, res, next) {
    let webdavClient=createWebdavClient(req.user.uid,req.user.password);

    let link=webdavClient.getFileDownloadLink("/"+req.params.filename);
    res.status(200).send(link);
  })
);
app.put('/alfresco/:filename',
  asyncHandler(async function(req, res, next) {
    let webdavClient=createWebdavClient(req.user.uid,req.user.password);

    let fileGroup;
    const bb = busboy({ headers: req.headers });
    bb.on('field', (name, val, info) => {
      if (name=="fileGroup") fileGroup=val;
    });
    bb.on('file', (fieldname, file, info) => {
      console.log(`Upload of '${info.filename}' started`);

      // Create a write stream of the new file
      const wstream = webdavClient.createWriteStream("/"+req.params.filename);
      let m = meter();

      // On finish of the upload
      file.on('close', async () => {
        console.log(`Upload of '${info.filename}' finished`);

        const result = await runner.query(req,`
          mutation {
            createAlfresco(
              input: {
                alfresco: {
                  user: "${req.user.email}",
                  name: "${req.params.filename}",
                  size: "${m.bytes}",
                  fileGroup: "${fileGroup}"
                }
              }
            ) {
              alfresco {
                user
                name
                size
              }
            }
          }`,
          { role: req.user.role }
        );
        console.log(result);

        res.status(200).send("OK");
      });
      wstream.on('error', function (err) {
        next(err);
      });
      // Pipe it trough
      file.pipe(m).pipe(wstream);
    });
    req.pipe(bb);
  })
);
app.delete('/alfresco/:filename',
  asyncHandler(async function(req, res, next) {
    let webdavClient=createWebdavClient(req.user.uid,req.user.password);

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

// app.get('/prefs/:name',
//   asyncHandler(async function(req, res) {
//     const getPref=async function(user,pref) {
//       const result=await runner.query(req,`
//         {
//           allPreferences (condition: { user:"${user}" pref:"${pref}" }) {
//             nodes {
//               value
//             }
//           }
//         }`
//       );
//       if (result.errors)
//         return result;
//       if (result.data.allPreferences.nodes.length==0)
//         return null;
//       return result.data.allPreferences.nodes[0].value;
//     };

//     let result;
    
//     result=await getPref(req.user.uid,req.params.name);
//     if (result && result.errors) {
//       res.status(500).send(result);
//       return;
//     }
//     if (result) {
//       res.status(200).send(result);
//       return;
//     }

//     result=await getPref("@"+req.user.role,req.params.name);
//     if (result && result.errors) {
//       res.status(500).send(result);
//       return;
//     }
//     if (result) {
//       res.status(200).send(result);
//       return;
//     }

//     result=await getPref("*",req.params.name);
//     if (result && result.errors) {
//       res.status(500).send(result);
//       return;
//     }
//     if (result) {
//       res.status(200).send(result);
//       return;
//     }

//     res.status(200).send("");
//   })
// );
// app.put('/prefs/:name',
//   asyncHandler(async function(req, res) {
//     if (!req.body) return res.status(400).json({ message: "Missing body" });

//     const resultDel = await runner.query(req,`
//       mutation {
//         deletePreferenceByUserAndPref(input: { user: "${req.user.uid}" pref: "${req.params.name}" }) {
//           deletedPreferenceId
//         }
//       }`
//     );

//     if (resultDel.errors && !resultDel.errors[0].message.includes("because no values you can delete were found matching these criteria")) {
//       res.status(500).send(resultDel);
//       return;
//     }

//     const result = await runner.query(req,`
//       mutation {
//         createPreference(
//           input: {
//             preference: {
//               user: "${req.user.uid}",
//               pref: "${req.params.name}",
//               value: "${req.body}"
//             }
//           }
//         ) {
//           preference {
//             user
//             pref
//             value
//           }
//         }
//       }`
//     );
    
//     if (result.errors)
//       res.status(500).send(result);
//     else
//       res.status(200).send("OK");
//   })
// );

app.use('/graphql', function (req, res, next) {
  req.body.query=req.body.query.replace("§uid",req.user.uid);
  req.body.query=req.body.query.replace("§email",req.user.email);
  next();
});

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
        'user.uid': req.user.uid,
        'user.email': req.user.email,
      }),
      appendPlugins: [PgOrderByRelatedPlugin,ConnectionFilterPlugin,AtomicMutationsPlugin],
      async additionalGraphQLContextFromRequest(req, res) {
        return {
          // Additional context needed by the plugin
          mutationAtomicityContext: getMutationAtomicityContext(req),
        };
      },
    }
));

app.use(function(err, req, res, next) {
  if (err.name == 'UnauthorizedError') {
    res.status(401).send('Invalid token');
  }
  else if ('stack' in err) {
    console.error(err.stack);
    res.status(500).send(err.stack);
  }
  else {
    console.error(err);
    res.status(500).send(err);
  }
});

var privateKey  = fs.readFileSync(process.env.KEY_FILE, 'utf8');
var certificate = fs.readFileSync(process.env.CERT_FILE, 'utf8');
var credentials = {key: privateKey, cert: certificate};

var httpsServer = https.createServer(credentials, app);
httpsServer.listen(process.env.PORT || 8443, () => {
  console.log('Server running on port %d', process.env.PORT);
});
