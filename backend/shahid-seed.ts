import { Pool } from "pg";
import { randomUUID } from "node:crypto";
import { hashPassword } from "./shahid-auth";

const url=process.env.DATABASE_URL;
const password=process.env.SHAHID_SEED_PASSWORD;
if(process.env.ALLOW_DEMO_SEED!=="true") throw new Error("Set ALLOW_DEMO_SEED=true for an explicit non-production demo seed");
if(!url||!password||password.length<12) throw new Error("DATABASE_URL and SHAHID_SEED_PASSWORD (>=12 chars) are required");

const pool=new Pool({connectionString:url});
try{
 const universityId=randomUUID();
 await pool.query("INSERT INTO universities(id,name,country_code) VALUES($1,'SHAHID Pilot University','EG') ON CONFLICT DO NOTHING",[universityId]);
 const uni=(await pool.query("SELECT id FROM universities WHERE name='SHAHID Pilot University' LIMIT 1")).rows[0].id;
 const professorId=randomUUID(),studentIds=[randomUUID(),randomUUID(),randomUUID()];
 await pool.query("INSERT INTO users(id,university_id,role,full_name,email,password_hash) VALUES($1,$2,'professor','SHAHID Pilot Professor','professor@shahid.local',$3) ON CONFLICT DO NOTHING",[professorId,uni,hashPassword(password)]);
 for(let i=0;i<studentIds.length;i++) await pool.query("INSERT INTO users(id,university_id,role,full_name,email,password_hash) VALUES($1,$2,'student',$3,$4,$5) ON CONFLICT DO NOTHING",[studentIds[i],uni,"SHAHID Student "+(i+1),"student"+(i+1)+"@shahid.local",hashPassword(password)]);
 const courseId=randomUUID();await pool.query("INSERT INTO courses(id,university_id,code,title) VALUES($1,$2,'CYB-PILOT','Cybersecurity Attendance Pilot') ON CONFLICT(university_id,code) DO NOTHING",[courseId,uni]);
 const course=(await pool.query("SELECT id FROM courses WHERE university_id=$1 AND code='CYB-PILOT' LIMIT 1",[uni])).rows[0].id;
 const sectionId=randomUUID();await pool.query("INSERT INTO sections(id,course_id,instructor_id,term) VALUES($1,$2,$3,'Pilot') ON CONFLICT DO NOTHING",[sectionId,course,professorId]);
 const section=(await pool.query("SELECT id FROM sections WHERE course_id=$1 AND instructor_id=$2 LIMIT 1",[course,professorId])).rows[0].id;
 for(const sid of studentIds) await pool.query("INSERT INTO enrollments(id,section_id,student_id) VALUES($1,$2,$3) ON CONFLICT(section_id,student_id) DO NOTHING",[randomUUID(),section,sid]);
 const sessionId=randomUUID();await pool.query("INSERT INTO class_sessions(id,section_id,status) VALUES($1,$2,'active') ON CONFLICT DO NOTHING",[sessionId,section]);
 console.log(JSON.stringify({universityId:uni,professor:"professor@shahid.local",students:studentIds.map((_,i)=>"student"+(i+1)+"@shahid.local"),password,sessionId},null,2));
}finally{await pool.end();}
