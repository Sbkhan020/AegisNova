const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
let token: string | null = null;
export const setToken=(value:string|null)=>{token=value};
function errMessage(data:any, status:number){
 const d = data?.detail ?? data?.error;
 if (typeof d === 'string') return d;
 if (Array.isArray(d)) return d.map(x => typeof x === 'string' ? x : (x?.msg ?? JSON.stringify(x))).join('; ');
 if (d && typeof d === 'object') return d.msg ?? JSON.stringify(d);
 return `Request failed (${status})`;
}
async function request(path:string, options:RequestInit={}){
 const headers=new Headers(options.headers); if(token) headers.set('Authorization',`Bearer ${token}`); if(options.body && !(options.body instanceof FormData)) headers.set('Content-Type','application/json');
 const res=await fetch(`${API}${path}`,{...options,headers}); const data=await res.json().catch(()=>({detail:'Unexpected server response'})); if(!res.ok) throw new Error(errMessage(data, res.status)); return data;
}
export const api={register:(body:unknown)=>request('/api/auth/register',{method:'POST',body:JSON.stringify(body)}),login:(body:unknown)=>request('/api/auth/login',{method:'POST',body:JSON.stringify(body)}),me:()=>request('/api/auth/me'),dashboard:()=>request('/api/dashboard'),scans:()=>request('/api/scans'),detail:(id:number)=>request(`/api/scans/${id}`),url:(url:string)=>request('/api/scans/url',{method:'POST',body:JSON.stringify({url})}),email:(content:string)=>request('/api/scans/email',{method:'POST',body:JSON.stringify({content})}),network:(scope:string)=>request('/api/scans/network',{method:'POST',body:JSON.stringify({scope})}),file:(file:File)=>{const f=new FormData();f.append('file',file);return request('/api/scans/file',{method:'POST',body:f})},admin:()=>request('/api/admin/overview')};
