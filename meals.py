"""나이스 급식 조회. 인증키는 서버 환경변수에서만 사용합니다."""
import datetime as dt
import calendar
import html
import json
import os
import re
import time
from urllib.parse import urlencode
from urllib.request import urlopen

class MealError(Exception): pass
_cache={}

def request_rows(service,params):
    query={'Type':'json','pIndex':1,'pSize':100,**params}
    if os.getenv('NEIS_API_KEY'):query['KEY']=os.environ['NEIS_API_KEY']
    try:
        with urlopen('https://open.neis.go.kr/hub/'+service+'?'+urlencode(query),timeout=10) as response:
            data=json.loads(response.read(2_000_000).decode('utf-8-sig'))
    except Exception as exc:
        raise MealError('급식 제공 서버에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요.') from exc
    result=data.get('RESULT',{})
    if result.get('CODE')=='INFO-200':return []
    if result and result.get('CODE')!='INFO-000':raise MealError('나이스 API 요청이 거절되었습니다. 인증키와 호출 한도를 확인하세요.')
    blocks=data.get(service)
    if not isinstance(blocks,list):raise MealError('급식 제공 서버의 응답 형식이 올바르지 않습니다.')
    rows=[]
    for block in blocks:
        for head in block.get('head',[]):
            status=head.get('RESULT',{}).get('CODE')
            if status and status!='INFO-000':raise MealError('나이스 API 오류가 발생했습니다.')
        rows.extend(block.get('row',[]))
    return rows

def lines(value):
    return [html.unescape(re.sub('<[^>]*>','',part)).strip() for part in re.split(r'<br\s*/?>|\n',value or '',flags=re.I) if part.strip()]

def get_meals(date):
    monthly=len(date)==7
    day=dt.date.fromisoformat(date+'-01' if monthly else date)
    if (day.strftime('%Y-%m') if monthly else day.isoformat())!=date:raise ValueError('날짜 형식 오류')
    if monthly and not os.getenv('NEIS_API_KEY'):raise MealError('월별 급식 조회를 위해 서버에 나이스 인증키를 설정해 주세요.')
    key=(date,os.getenv('NEIS_API_KEY',''))
    cached=_cache.get(key)
    if cached and cached[0]>time.time():return cached[1]
    school_key=('school',os.getenv('NEIS_API_KEY',''))
    school=_cache.get(school_key)
    if not school or school[0]<time.time():
        matches=request_rows('schoolInfo',{'SCHUL_NM':'세명컴퓨터고등학교'})
        matches=[r for r in matches if r.get('SCHUL_NM')=='세명컴퓨터고등학교' and r.get('LCTN_SC_NM')=='서울특별시']
        if len(matches)!=1:raise MealError('세명컴퓨터고등학교 정보를 확인하지 못했습니다. 나이스 인증키를 설정하고 다시 시도해 주세요.')
        school=(time.time()+86400,matches[0]);_cache[school_key]=school
    info=school[1]
    dates={'MLSV_FROM_YMD':day.strftime('%Y%m%d'),'MLSV_TO_YMD':day.replace(day=calendar.monthrange(day.year,day.month)[1]).strftime('%Y%m%d')} if monthly else {'MLSV_YMD':day.strftime('%Y%m%d')}
    rows=request_rows('mealServiceDietInfo',{'ATPT_OFCDC_SC_CODE':info['ATPT_OFCDC_SC_CODE'],'SD_SCHUL_CODE':info['SD_SCHUL_CODE'],**dates})
    meals=[]
    days={}
    for r in rows:
        raw_date=str(r.get('MLSV_YMD',''))
        if (not raw_date.startswith(day.strftime('%Y%m')) if monthly else raw_date!=day.strftime('%Y%m%d')) or str(r.get('SD_SCHUL_CODE'))!=str(info['SD_SCHUL_CODE']):continue
        meal={'name':r.get('MMEAL_SC_NM','급식'),'dishes':lines(r.get('DDISH_NM','')),'calories':r.get('CAL_INFO',''),'nutrition':lines(r.get('NTR_INFO','')),'origins':lines(r.get('ORPLC_INFO',''))}
        meals.append(meal)
        formatted=dt.datetime.strptime(raw_date,'%Y%m%d').date().isoformat()
        days.setdefault(formatted,[]).append(meal)
    payload={'date':date,'school':info['SCHUL_NM'],'meals':meals,'source':'나이스 교육정보 개방 포털'}
    if monthly:payload={'month':date,'school':info['SCHUL_NM'],'days':days,'source':'나이스 교육정보 개방 포털'}
    if len(_cache)>128:_cache.clear()
    _cache[key]=(time.time()+(3600 if meals else 600),payload)
    return payload
