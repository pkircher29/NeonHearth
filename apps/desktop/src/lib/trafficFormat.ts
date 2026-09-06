import type {TrafficPoint} from './api/hostMonitor';
export function formatBytes(value:number|null|undefined):string {
  if(value===null||value===undefined||!Number.isFinite(value)||value<0)return 'Not measured';
  const units=['B','KiB','MiB','GiB','TiB','PiB'];let index=0;
  while(value>=1024&&index<units.length-1){value/=1024;index++;}
  return `${value.toFixed(index?1:0)} ${units[index]}`;
}
export function trafficPath(points:TrafficPoint[],field:'sent_bytes'|'received_bytes',start:number,end:number,max:number,gapSeconds:number):string {
  let previous=0;let previousInterval=0;
  return points.map(p=>{const gap=Math.max(5,Math.min(gapSeconds,Math.max(previousInterval,p.measured_ms)/1000));const move=!previous||p.at-previous>gap*1.5;previous=p.at;previousInterval=p.measured_ms;const x=Math.max(0,Math.min(900,(p.at-start)/Math.max(1,end-start)*900));const rate=p[field]*1000/Math.max(1,p.measured_ms);return `${move?'M':'L'}${x.toFixed(2)} ${(180-Math.min(1,rate/Math.max(1,max))*160).toFixed(2)}`;}).join(' ');
}
export function csvCell(value:unknown):string {
  let text=String(value??'');if(/^[\s]*[=+@-]/.test(text)||/^[\t\r\n]/.test(text))text=`'${text}`;
  return `"${text.replaceAll('"','""')}"`;
}
export function trafficCsv(rows:unknown[][]):string{return rows.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';}
