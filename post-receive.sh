#!/bin/bash
while read oldrev newrev ref
do
if [[ $ref =~ .*/main$ ]];
then
echo "Main ref received.  Deploying main branch to production..."
pwd
git --work-tree=$HOME/frontend --git-dir=$HOME/frontend/.git checkout -f
pm2 start update.sh --no-autorestart
else
echo "Ref $ref successfully received.  Doing nothing: only the main branch may be deployed on this server."
fi
done
