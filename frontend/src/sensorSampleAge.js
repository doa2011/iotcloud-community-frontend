// Sample age and transport liveness have independent limits.
export function sampleLimit(id,sample){
 if(sample.max_age_ms===undefined)return 20000;
 return ['pm25','pm10'].includes(id)&&Number.isInteger(sample.max_age_ms)&&sample.max_age_ms>=1&&sample.max_age_ms<=3600000?sample.max_age_ms:0;
}
export function sampleFresh(id,sample,elapsed){
 return sample?.valid===true&&Number.isFinite(sample.value)&&Number.isInteger(sample.age_ms)&&sample.age_ms>=0&&Number.isFinite(elapsed)&&elapsed>=0&&elapsed<20000&&sample.age_ms+elapsed<sampleLimit(id,sample);
}
