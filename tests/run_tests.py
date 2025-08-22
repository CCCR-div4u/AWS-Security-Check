#!/usr/bin/env python3
"""
테스트 실행 스크립트
모든 테스트를 실행하고 결과를 보고합니다.
"""

import unittest
import sys
import os
import time
from io import StringIO

# 프로젝트 루트 디렉터리를 Python 경로에 추가
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

def run_test_suite():
    """전체 테스트 스위트 실행"""
    
    print("=" * 80)
    print("AWS 보안 대시보드 테스트 스위트")
    print("=" * 80)
    print()
    
    # 테스트 디스커버리
    test_dir = os.path.dirname(os.path.abspath(__file__))
    loader = unittest.TestLoader()
    
    # 개별 테스트 모듈 로드
    test_modules = [
        'test_basic_simple',
        'test_aws_connection', 
        'test_integration'
    ]
    
    total_tests = 0
    total_failures = 0
    total_errors = 0
    total_skipped = 0
    
    for module_name in test_modules:
        print(f"📋 {module_name.replace('_', ' ').title()} 실행 중...")
        print("-" * 60)
        
        try:
            # 테스트 모듈 로드
            suite = loader.loadTestsFromName(module_name)
            
            # 테스트 실행
            stream = StringIO()
            runner = unittest.TextTestRunner(
                stream=stream,
                verbosity=2,
                buffer=True
            )
            
            start_time = time.time()
            result = runner.run(suite)
            end_time = time.time()
            
            # 결과 출력
            output = stream.getvalue()
            print(output)
            
            # 통계 업데이트
            total_tests += result.testsRun
            total_failures += len(result.failures)
            total_errors += len(result.errors)
            total_skipped += len(result.skipped)
            
            # 모듈별 요약
            duration = end_time - start_time
            print(f"✅ {module_name}: {result.testsRun}개 테스트 완료 ({duration:.2f}초)")
            
            if result.failures:
                print(f"❌ 실패: {len(result.failures)}개")
                for test, traceback in result.failures:
                    print(f"   - {test}: {traceback.split('AssertionError:')[-1].strip()}")
            
            if result.errors:
                print(f"🚨 오류: {len(result.errors)}개")
                for test, traceback in result.errors:
                    print(f"   - {test}: {traceback.split('Exception:')[-1].strip()}")
            
            if result.skipped:
                print(f"⏭️ 건너뜀: {len(result.skipped)}개")
                for test, reason in result.skipped:
                    print(f"   - {test}: {reason}")
            
            print()
            
        except Exception as e:
            print(f"❌ {module_name} 로드 실패: {e}")
            total_errors += 1
            print()
    
    # 전체 요약
    print("=" * 80)
    print("📊 테스트 결과 요약")
    print("=" * 80)
    print(f"총 테스트: {total_tests}개")
    print(f"성공: {total_tests - total_failures - total_errors}개")
    print(f"실패: {total_failures}개")
    print(f"오류: {total_errors}개")
    print(f"건너뜀: {total_skipped}개")
    print()
    
    # 성공률 계산
    if total_tests > 0:
        success_rate = ((total_tests - total_failures - total_errors) / total_tests) * 100
        print(f"성공률: {success_rate:.1f}%")
    else:
        print("실행된 테스트가 없습니다.")
    
    print()
    
    # 최종 결과
    if total_failures == 0 and total_errors == 0:
        print("🎉 모든 테스트가 성공적으로 완료되었습니다!")
        return 0
    else:
        print("⚠️ 일부 테스트가 실패했습니다. 위의 세부 정보를 확인하세요.")
        return 1

def run_specific_test(test_name):
    """특정 테스트 실행"""
    print(f"🔍 특정 테스트 실행: {test_name}")
    print("-" * 60)
    
    try:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(test_name)
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        if result.wasSuccessful():
            print(f"✅ {test_name} 테스트 성공!")
            return 0
        else:
            print(f"❌ {test_name} 테스트 실패!")
            return 1
            
    except Exception as e:
        print(f"❌ 테스트 실행 오류: {e}")
        return 1

def show_help():
    """도움말 표시"""
    print("AWS 보안 대시보드 테스트 실행기")
    print()
    print("사용법:")
    print("  python run_tests.py                    # 모든 테스트 실행")
    print("  python run_tests.py <test_name>        # 특정 테스트 실행")
    print("  python run_tests.py --help             # 도움말 표시")
    print()
    print("예시:")
    print("  python run_tests.py test_basic.TestAWSCredentialsValidation")
    print("  python run_tests.py test_aws_connection.TestAWSConnectionMocked")
    print("  python run_tests.py test_integration.TestFullWorkflowIntegration")
    print()
    print("환경 변수:")
    print("  AWS_ACCESS_KEY_ID      # 실제 AWS 연결 테스트용")
    print("  AWS_SECRET_ACCESS_KEY  # 실제 AWS 연결 테스트용")
    print("  AWS_DEFAULT_REGION     # 기본 리전 (기본값: ap-northeast-2)")

def check_dependencies():
    """필요한 의존성 확인"""
    required_modules = [
        'boto3',
        'botocore',
        'pandas',
        'plotly',
        'streamlit'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print("❌ 누락된 의존성:")
        for module in missing_modules:
            print(f"   - {module}")
        print()
        print("다음 명령으로 설치하세요:")
        print(f"pip install {' '.join(missing_modules)}")
        return False
    
    return True

if __name__ == '__main__':
    # 의존성 확인
    if not check_dependencies():
        sys.exit(1)
    
    # 명령행 인수 처리
    if len(sys.argv) == 1:
        # 모든 테스트 실행
        exit_code = run_test_suite()
    elif len(sys.argv) == 2:
        arg = sys.argv[1]
        if arg in ['--help', '-h']:
            show_help()
            exit_code = 0
        else:
            # 특정 테스트 실행
            exit_code = run_specific_test(arg)
    else:
        print("❌ 잘못된 인수입니다. --help를 참조하세요.")
        exit_code = 1
    
    sys.exit(exit_code)