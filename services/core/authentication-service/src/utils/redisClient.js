'use strict';
const Redis=require('ioredis');const config=require('./config');
function redisClient(options={}){
 return config.redis.url?new Redis(config.redis.url,options):new Redis({host:config.redis.host,port:config.redis.port,password:config.redis.password,db:config.redis.db,...options});
}
module.exports={redisClient};
