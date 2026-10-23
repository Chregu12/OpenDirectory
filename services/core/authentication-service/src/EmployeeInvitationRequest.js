'use strict';
const {invitationRequest:factory}=require('../../../../packages/employee-invitation-request');
const invitationRequest=({issuer=process.env.OIDC_ISSUER||'http://localhost:3001',jwksUri=process.env.JWKS_URI||'http://oauth-provider:3010/.well-known/jwks.json'}={})=>factory({issuer,jwksUri,loadJose:()=>import('jose')});
module.exports={invitationRequest};
