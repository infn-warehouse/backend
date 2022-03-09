#!/bin/bash
pm2 delete index
npm install
pm2 start node index.js
pm2 delete update