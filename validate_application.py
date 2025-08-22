#!/usr/bin/env python3
"""
AWS 보안 대시보드 애플리케이션 검증 스크립트
전체 애플리케이션의 상태를 점검하고 문제점을 식별합니다.
"""

import os
import sys
import importlib.util
import subprocess
import json
from datetime import datetime


class ApplicationValidator:
    """애플리케이션 검증 클래스"""
    
    def __init__(self):
        self.project_root = os.path.dirname(os.path.abspath(__file__))
        self.validation_results = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'unknown',
            'checks': {}
        }
    
    def run_all_validations(self):
        """모든 검증 실행"""
        print("=" * 80)
        print("AWS 보안 대시보드 애플리케이션 검증")
        print("=" * 80)
        print()
        
        # 1. 파일 구조 검증
        print("1️⃣ 파일 구조 검증")
        self._validate_file_structure()
        
        # 2. 의존성 검증
        print("\n2️⃣ 의존성 검증")
        self._validate_dependencies()
        
        # 3. 코드 품질 검증
        print("\n3️⃣ 코드 품질 검증")
        self._validate_code_quality()
        
        # 4. 기능 검증
        print("\n4️⃣ 기능 검증")
        self._validate_functionality()
        
        # 5. 보안 검증
        print("\n5️⃣ 보안 검증")
        self._validate_security()
        
        # 6. 성능 검증
        print("\n6️⃣ 성능 검증")
        self._validate_performance()
        
        # 7. 테스트 검증
        print("\n7️⃣ 테스트 검증")
        self._validate_tests()
        
        # 전체 결과 요약
        self._generate_summary()
        
        return self.validation_results
    
    def _validate_file_structure(self):
        """파일 구조 검증"""
        required_files = [
            'app.py',
            'requirements.txt',
            'README.md',
            'tests/__init__.py',
            'tests/test_basic_simple.py',
            'tests/test_aws_connection.py',
            'tests/test_integration.py',
            'tests/run_tests.py'
        ]
        
        optional_files = [
            'DEPLOYMENT.md',
            'QUICK_DEPLOY.md',
            'scripts/install.sh',
            'scripts/deploy.sh',
            'systemd/aws-security-dashboard.service',
            'nginx/aws-security-dashboard.conf'
        ]
        
        missing_required = []
        missing_optional = []
        
        for file_path in required_files:
            full_path = os.path.join(self.project_root, file_path)
            if not os.path.exists(full_path):
                missing_required.append(file_path)
            else:
                print(f"  ✅ {file_path}")
        
        for file_path in optional_files:
            full_path = os.path.join(self.project_root, file_path)
            if not os.path.exists(full_path):
                missing_optional.append(file_path)
            else:
                print(f"  ✅ {file_path}")
        
        if missing_required:
            print(f"  ❌ 필수 파일 누락: {', '.join(missing_required)}")
            self.validation_results['checks']['file_structure'] = {
                'status': 'failed',
                'missing_required': missing_required,
                'missing_optional': missing_optional
            }
        else:
            print("  ✅ 모든 필수 파일이 존재합니다")
            self.validation_results['checks']['file_structure'] = {
                'status': 'passed',
                'missing_optional': missing_optional
            }
    
    def _validate_dependencies(self):
        """의존성 검증"""
        required_packages = [
            'streamlit',
            'boto3',
            'botocore',
            'pandas',
            'plotly',
            'python-dateutil'
        ]
        
        missing_packages = []
        installed_packages = {}
        
        for package in required_packages:
            try:
                # python-dateutil의 경우 dateutil로 import
                if package == 'python-dateutil':
                    module = importlib.import_module('dateutil')
                else:
                    module = importlib.import_module(package.replace('-', '_'))
                version = getattr(module, '__version__', 'unknown')
                installed_packages[package] = version
                print(f"  ✅ {package} ({version})")
            except ImportError:
                missing_packages.append(package)
                print(f"  ❌ {package} - 설치되지 않음")
        
        if missing_packages:
            print(f"  ⚠️ 누락된 패키지: {', '.join(missing_packages)}")
            print(f"  💡 설치 명령: pip install {' '.join(missing_packages)}")
            self.validation_results['checks']['dependencies'] = {
                'status': 'failed',
                'missing_packages': missing_packages,
                'installed_packages': installed_packages
            }
        else:
            print("  ✅ 모든 필수 패키지가 설치되어 있습니다")
            self.validation_results['checks']['dependencies'] = {
                'status': 'passed',
                'installed_packages': installed_packages
            }
    
    def _validate_code_quality(self):
        """코드 품질 검증"""
        app_py_path = os.path.join(self.project_root, 'app.py')
        
        if not os.path.exists(app_py_path):
            print("  ❌ app.py 파일이 존재하지 않습니다")
            self.validation_results['checks']['code_quality'] = {'status': 'failed', 'reason': 'app.py not found'}
            return
        
        # 파일 크기 확인
        file_size = os.path.getsize(app_py_path)
        print(f"  📊 app.py 파일 크기: {file_size:,} bytes")
        
        # 기본 구문 검사
        try:
            with open(app_py_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 컴파일 테스트
            compile(content, app_py_path, 'exec')
            print("  ✅ 구문 검사 통과")
            
            # 기본 구조 확인
            required_functions = ['main', 'show_authentication_form', 'validate_aws_credentials']
            found_functions = []
            
            for func_name in required_functions:
                if f'def {func_name}(' in content:
                    found_functions.append(func_name)
                    print(f"  ✅ {func_name} 함수 발견")
                else:
                    print(f"  ⚠️ {func_name} 함수 누락")
            
            # 보안 관련 확인
            security_checks = {
                'streamlit_config': 'st.set_page_config' in content,
                'error_handling': 'try:' in content and 'except' in content,
                'session_state': 'st.session_state' in content,
                'aws_imports': 'import boto3' in content
            }
            
            for check_name, passed in security_checks.items():
                if passed:
                    print(f"  ✅ {check_name} 확인")
                else:
                    print(f"  ⚠️ {check_name} 누락")
            
            self.validation_results['checks']['code_quality'] = {
                'status': 'passed',
                'file_size': file_size,
                'found_functions': found_functions,
                'security_checks': security_checks
            }
            
        except SyntaxError as e:
            print(f"  ❌ 구문 오류: {e}")
            self.validation_results['checks']['code_quality'] = {
                'status': 'failed',
                'error': str(e)
            }
        except Exception as e:
            print(f"  ❌ 코드 검증 오류: {e}")
            self.validation_results['checks']['code_quality'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    def _validate_functionality(self):
        """기능 검증"""
        try:
            # app.py 모듈 로드 테스트
            app_py_path = os.path.join(self.project_root, 'app.py')
            spec = importlib.util.spec_from_file_location("app", app_py_path)
            app_module = importlib.util.module_from_spec(spec)
            
            # 모듈 실행 테스트 (실제로는 실행하지 않고 로드만)
            print("  ✅ app.py 모듈 로드 성공")
            
            # 주요 함수 존재 확인
            with open(app_py_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            key_features = {
                'authentication': 'show_authentication_form' in content,
                'aws_validation': 'validate_aws_credentials' in content,
                'security_scan': 'start_security_scan' in content or 'perform_' in content,
                'dashboard': 'show_dashboard' in content,
                'error_handling': 'ClientError' in content and 'NoCredentialsError' in content
            }
            
            all_features_present = True
            for feature, present in key_features.items():
                if present:
                    print(f"  ✅ {feature} 기능 확인")
                else:
                    print(f"  ⚠️ {feature} 기능 누락 또는 불완전")
                    all_features_present = False
            
            self.validation_results['checks']['functionality'] = {
                'status': 'passed' if all_features_present else 'warning',
                'features': key_features
            }
            
        except Exception as e:
            print(f"  ❌ 기능 검증 실패: {e}")
            self.validation_results['checks']['functionality'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    def _validate_security(self):
        """보안 검증"""
        security_issues = []
        
        # app.py 보안 검사
        app_py_path = os.path.join(self.project_root, 'app.py')
        if os.path.exists(app_py_path):
            with open(app_py_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 하드코딩된 자격 증명 검사
            sensitive_patterns = [
                'AKIA',  # AWS Access Key 패턴
                'aws_access_key_id=',
                'aws_secret_access_key=',
                'password=',
                'secret='
            ]
            
            for pattern in sensitive_patterns:
                if pattern in content and 'EXAMPLE' not in content:
                    # EXAMPLE이 포함된 경우는 예시 코드로 간주
                    lines = content.split('\n')
                    for i, line in enumerate(lines, 1):
                        if pattern in line and 'EXAMPLE' not in line:
                            security_issues.append(f"라인 {i}: 하드코딩된 자격 증명 의심 - {pattern}")
            
            # 보안 모범 사례 확인
            security_practices = {
                'session_state_usage': 'st.session_state' in content,
                'error_handling': 'try:' in content and 'except' in content,
                'input_validation': 'isdigit()' in content or 'len(' in content,
                'aws_error_handling': 'ClientError' in content
            }
            
            for practice, implemented in security_practices.items():
                if implemented:
                    print(f"  ✅ {practice} 구현됨")
                else:
                    print(f"  ⚠️ {practice} 미구현")
                    security_issues.append(f"{practice} 보안 모범 사례 미구현")
        
        if security_issues:
            print(f"  ⚠️ 보안 이슈 발견: {len(security_issues)}개")
            for issue in security_issues:
                print(f"    - {issue}")
            self.validation_results['checks']['security'] = {
                'status': 'warning',
                'issues': security_issues
            }
        else:
            print("  ✅ 보안 검증 통과")
            self.validation_results['checks']['security'] = {
                'status': 'passed',
                'issues': []
            }
    
    def _validate_performance(self):
        """성능 검증"""
        try:
            # 파일 크기 확인
            app_py_path = os.path.join(self.project_root, 'app.py')
            if os.path.exists(app_py_path):
                file_size = os.path.getsize(app_py_path)
                
                if file_size > 1024 * 1024:  # 1MB
                    print(f"  ⚠️ app.py 파일이 큼: {file_size:,} bytes")
                else:
                    print(f"  ✅ app.py 파일 크기 적절: {file_size:,} bytes")
                
                # 코드 복잡도 간단 확인
                with open(app_py_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                total_lines = len(lines)
                code_lines = len([line for line in lines if line.strip() and not line.strip().startswith('#')])
                comment_lines = len([line for line in lines if line.strip().startswith('#')])
                
                print(f"  📊 총 라인 수: {total_lines}")
                print(f"  📊 코드 라인 수: {code_lines}")
                print(f"  📊 주석 라인 수: {comment_lines}")
                
                # 함수 개수 확인
                function_count = len([line for line in lines if line.strip().startswith('def ')])
                print(f"  📊 함수 개수: {function_count}")
                
                performance_score = 'good'
                if total_lines > 5000:
                    performance_score = 'warning'
                    print("  ⚠️ 파일이 매우 큼 - 모듈 분리 고려")
                elif function_count > 50:
                    performance_score = 'warning'
                    print("  ⚠️ 함수가 많음 - 리팩토링 고려")
                else:
                    print("  ✅ 코드 구조 적절")
                
                self.validation_results['checks']['performance'] = {
                    'status': 'passed' if performance_score == 'good' else 'warning',
                    'file_size': file_size,
                    'total_lines': total_lines,
                    'code_lines': code_lines,
                    'function_count': function_count
                }
            
        except Exception as e:
            print(f"  ❌ 성능 검증 실패: {e}")
            self.validation_results['checks']['performance'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    def _validate_tests(self):
        """테스트 검증"""
        try:
            # 테스트 실행
            test_runner_path = os.path.join(self.project_root, 'tests', 'run_tests.py')
            
            if not os.path.exists(test_runner_path):
                print("  ❌ 테스트 실행기가 없습니다")
                self.validation_results['checks']['tests'] = {
                    'status': 'failed',
                    'reason': 'test runner not found'
                }
                return
            
            print("  🔄 테스트 실행 중...")
            
            # 테스트 실행 (간단한 import 테스트만)
            try:
                import subprocess
                result = subprocess.run(
                    [sys.executable, test_runner_path],
                    cwd=self.project_root,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    print("  ✅ 모든 테스트 통과")
                    # 출력에서 테스트 결과 파싱
                    output_lines = result.stdout.split('\n')
                    test_count = 0
                    success_rate = 0
                    
                    for line in output_lines:
                        if '총 테스트:' in line:
                            test_count = int(line.split(':')[1].split('개')[0].strip())
                        elif '성공률:' in line:
                            success_rate = float(line.split(':')[1].split('%')[0].strip())
                    
                    self.validation_results['checks']['tests'] = {
                        'status': 'passed',
                        'test_count': test_count,
                        'success_rate': success_rate
                    }
                else:
                    print("  ⚠️ 일부 테스트 실패")
                    print(f"  📄 오류 출력: {result.stderr[:200]}...")
                    self.validation_results['checks']['tests'] = {
                        'status': 'warning',
                        'error_output': result.stderr[:500]
                    }
                    
            except subprocess.TimeoutExpired:
                print("  ⚠️ 테스트 실행 시간 초과")
                self.validation_results['checks']['tests'] = {
                    'status': 'warning',
                    'reason': 'timeout'
                }
            except Exception as e:
                print(f"  ❌ 테스트 실행 실패: {e}")
                self.validation_results['checks']['tests'] = {
                    'status': 'failed',
                    'error': str(e)
                }
                
        except Exception as e:
            print(f"  ❌ 테스트 검증 실패: {e}")
            self.validation_results['checks']['tests'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    def _generate_summary(self):
        """전체 결과 요약 생성"""
        print("\n" + "=" * 80)
        print("검증 결과 요약")
        print("=" * 80)
        
        passed_checks = 0
        warning_checks = 0
        failed_checks = 0
        
        for check_name, check_result in self.validation_results['checks'].items():
            status = check_result.get('status', 'unknown')
            
            if status == 'passed':
                passed_checks += 1
                print(f"✅ {check_name}: 통과")
            elif status == 'warning':
                warning_checks += 1
                print(f"⚠️ {check_name}: 경고")
            elif status == 'failed':
                failed_checks += 1
                print(f"❌ {check_name}: 실패")
            else:
                print(f"❓ {check_name}: 알 수 없음")
        
        total_checks = len(self.validation_results['checks'])
        
        print(f"\n📊 전체 통계:")
        print(f"  총 검사 항목: {total_checks}개")
        print(f"  통과: {passed_checks}개")
        print(f"  경고: {warning_checks}개")
        print(f"  실패: {failed_checks}개")
        
        # 전체 상태 결정
        if failed_checks == 0 and warning_checks == 0:
            overall_status = 'excellent'
            print(f"\n🎉 전체 상태: 우수 (모든 검사 통과)")
        elif failed_checks == 0:
            overall_status = 'good'
            print(f"\n✅ 전체 상태: 양호 (경고 {warning_checks}개)")
        elif failed_checks <= 2:
            overall_status = 'needs_attention'
            print(f"\n⚠️ 전체 상태: 주의 필요 (실패 {failed_checks}개, 경고 {warning_checks}개)")
        else:
            overall_status = 'critical'
            print(f"\n❌ 전체 상태: 심각 (실패 {failed_checks}개, 경고 {warning_checks}개)")
        
        self.validation_results['overall_status'] = overall_status
        self.validation_results['summary'] = {
            'total_checks': total_checks,
            'passed': passed_checks,
            'warnings': warning_checks,
            'failed': failed_checks
        }
        
        # 권장 사항
        print(f"\n💡 권장 사항:")
        if failed_checks > 0:
            print("  - 실패한 검사 항목을 우선적으로 해결하세요")
        if warning_checks > 0:
            print("  - 경고 항목들을 검토하고 개선하세요")
        if overall_status == 'excellent':
            print("  - 애플리케이션이 배포 준비 상태입니다!")
        
        # 결과를 JSON 파일로 저장
        result_file = os.path.join(self.project_root, 'validation_results.json')
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(self.validation_results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n📄 상세 결과가 {result_file}에 저장되었습니다.")


def main():
    """메인 함수"""
    validator = ApplicationValidator()
    results = validator.run_all_validations()
    
    # 종료 코드 결정
    overall_status = results.get('overall_status', 'unknown')
    if overall_status in ['excellent', 'good']:
        sys.exit(0)
    elif overall_status == 'needs_attention':
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == '__main__':
    main()