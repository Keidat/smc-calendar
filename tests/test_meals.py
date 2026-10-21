import io
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import meals

class MealTests(unittest.TestCase):
    def setUp(self):meals._cache.clear()
    def tearDown(self):meals._cache.clear()
    def school(self):return [{'SCHUL_NM':'세명컴퓨터고등학교','LCTN_SC_NM':'서울특별시','ATPT_OFCDC_SC_CODE':'B10','SD_SCHUL_CODE':'7010537'}]
    def test_school_lookup_meal_parse_and_cache(self):
        rows=[{'SD_SCHUL_CODE':'7010537','MLSV_YMD':'20261020','MMEAL_SC_NM':'중식','DDISH_NM':'쌀밥<br/>국(1.2.)<BR>김치','CAL_INFO':'700 Kcal','NTR_INFO':'단백질:20<br/>지방:10'}]
        with patch.object(meals,'request_rows',side_effect=[self.school(),rows]) as request:
            result=meals.get_meals('2026-10-20')
            self.assertEqual(result['meals'][0]['dishes'],['쌀밥','국(1.2.)','김치'])
            self.assertEqual(meals.get_meals('2026-10-20'),result)
            self.assertEqual(request.call_count,2)
    def test_empty_and_wrong_date(self):
        with patch.object(meals,'request_rows',side_effect=[self.school(),[]]):self.assertEqual(meals.get_meals('2026-10-20')['meals'],[])
        with self.assertRaises(ValueError):meals.get_meals('2026-99-01')
    def test_monthly_range_and_grouping(self):
        rows=[{'SD_SCHUL_CODE':'7010537','MLSV_YMD':date,'MMEAL_SC_NM':'중식','DDISH_NM':'쌀밥'} for date in ['20240201','20240229','20240301']]
        with patch.dict(meals.os.environ,{'NEIS_API_KEY':'test-key'}),patch.object(meals,'request_rows',side_effect=[self.school(),rows]) as request:
            result=meals.get_meals('2024-02')
            self.assertEqual(set(result['days']),{'2024-02-01','2024-02-29'})
            self.assertEqual(request.call_args.args[1]['MLSV_TO_YMD'],'20240229')
            meals.get_meals('2024-02');self.assertEqual(request.call_count,2)
    def test_neis_no_data_and_error(self):
        with patch.object(meals,'urlopen',return_value=io.BytesIO(json.dumps({'RESULT':{'CODE':'INFO-200'}}).encode())):self.assertEqual(meals.request_rows('mealServiceDietInfo',{}),[])
        with patch.object(meals,'urlopen',return_value=io.BytesIO(json.dumps({'RESULT':{'CODE':'ERROR-290'}}).encode())):
            with self.assertRaises(meals.MealError):meals.request_rows('mealServiceDietInfo',{})
        with patch.object(meals,'urlopen',side_effect=TimeoutError):
            with self.assertRaises(meals.MealError):meals.request_rows('schoolInfo',{})

if __name__=='__main__':unittest.main()
