import {json,owner} from '../../_lib/auth.js';
export async function onRequestGet({request,env}){return json({owner:await owner(request,env)});}
