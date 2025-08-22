#!/usr/bin/env python3
"""
AWS 연결 테스트
실제 AWS 서비스와의 연결을 테스트합니다.
"""

import unittest
import os
import sys
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# 프로젝트 루트 디렉터리를 Python 경로에 추가
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


class TestAWSConnectionReal(unittest.TestCase):
    """실제 AWS 연결 테스트 (실제 자격 증명 필요)"""
    
    def setUp(self):
        """테스트 설정"""
        # 환경 변수에서 테스트용 AWS 자격 증명 확인
        self.aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.aws_region = os.getenv('AWS_DEFAULT_REGION', 'ap-northeast-2')
        
        # 실제 자격 증명이 없으면 테스트 스킵
        if not (self.aws_access_key and self.aws_secret_key):
            self.skipTest("실제 AWS 자격 증명이 환경 변수에 설정되지 않음")
    
    def test_real_aws_connection(self):
        """실제 AWS 연결 테스트"""
        try:
            session = boto3.Session(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                region_name=self.aws_region
            )
            
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            
            # 기본 검증
            self.assertIn('Account', identity)
            self.assertIn('Arn', identity)
            self.assertIn('UserId', identity)
            
            print(f"연결 성공 - 계정: {identity['Account']}")
            
        except (NoCredentialsError, ClientError) as e:
            self.fail(f"AWS 연결 실패: {e}")
    
    def test_real_iam_permissions(self):
        """실제 IAM 권한 테스트"""
        try:
            session = boto3.Session(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                region_name=self.aws_region
            )
            
            iam_client = session.client('iam')
            
            # IAM 계정 요약 조회 시도
            try:
                summary = iam_client.get_account_summary()
                self.assertIn('SummaryMap', summary)
                print("IAM 권한 확인됨")
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    print("IAM 권한 부족 (예상됨)")
                else:
                    raise
                    
        except (NoCredentialsError, ClientError) as e:
            self.fail(f"IAM 권한 테스트 실패: {e}")
    
    def test_real_s3_permissions(self):
        """실제 S3 권한 테스트"""
        try:
            session = boto3.Session(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                region_name=self.aws_region
            )
            
            s3_client = session.client('s3')
            
            # S3 버킷 목록 조회 시도
            try:
                buckets = s3_client.list_buckets()
                self.assertIn('Buckets', buckets)
                print(f"S3 권한 확인됨 - 버킷 수: {len(buckets['Buckets'])}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    print("S3 권한 부족 (예상됨)")
                else:
                    raise
                    
        except (NoCredentialsError, ClientError) as e:
            self.fail(f"S3 권한 테스트 실패: {e}")


class TestAWSConnectionMocked(unittest.TestCase):
    """Mock을 사용한 AWS 연결 테스트"""
    
    @patch('boto3.Session')
    def test_successful_sts_connection(self, mock_session):
        """STS 연결 성공 테스트"""
        # Mock 설정
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {
            'Account': '123456789012',
            'Arn': 'arn:aws:iam::123456789012:user/testuser',
            'UserId': 'AIDACKCEVSQ6C2EXAMPLE'
        }
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_sts_client
        mock_session.return_value = mock_session_instance
        
        # 테스트 실행
        session = boto3.Session(
            aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
            aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            region_name='ap-northeast-2'
        )
        
        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        
        # 검증
        self.assertEqual(identity['Account'], '123456789012')
        self.assertIn('testuser', identity['Arn'])
    
    @patch('boto3.Session')
    def test_iam_service_connection(self, mock_session):
        """IAM 서비스 연결 테스트"""
        # Mock 설정
        mock_iam_client = Mock()
        mock_iam_client.get_account_summary.return_value = {
            'SummaryMap': {
                'Users': 10,
                'Roles': 25,
                'Groups': 5,
                'Policies': 50,
                'MFADevices': 8
            }
        }
        mock_iam_client.list_users.return_value = {
            'Users': [
                {
                    'UserName': 'testuser1',
                    'Arn': 'arn:aws:iam::123456789012:user/testuser1',
                    'CreateDate': datetime.now(),
                    'Path': '/'
                },
                {
                    'UserName': 'testuser2',
                    'Arn': 'arn:aws:iam::123456789012:user/testuser2',
                    'CreateDate': datetime.now(),
                    'Path': '/'
                }
            ]
        }
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_iam_client
        mock_session.return_value = mock_session_instance
        
        # 테스트 실행
        session = boto3.Session()
        iam_client = session.client('iam')
        
        # 계정 요약 테스트
        summary = iam_client.get_account_summary()
        self.assertEqual(summary['SummaryMap']['Users'], 10)
        self.assertEqual(summary['SummaryMap']['Roles'], 25)
        
        # 사용자 목록 테스트
        users = iam_client.list_users()
        self.assertEqual(len(users['Users']), 2)
        self.assertEqual(users['Users'][0]['UserName'], 'testuser1')
    
    @patch('boto3.Session')
    def test_s3_service_connection(self, mock_session):
        """S3 서비스 연결 테스트"""
        # Mock 설정
        mock_s3_client = Mock()
        mock_s3_client.list_buckets.return_value = {
            'Buckets': [
                {
                    'Name': 'test-bucket-1',
                    'CreationDate': datetime.now()
                },
                {
                    'Name': 'test-bucket-2',
                    'CreationDate': datetime.now()
                }
            ]
        }
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {
                        'Type': 'CanonicalUser',
                        'ID': 'owner-id'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_s3_client
        mock_session.return_value = mock_session_instance
        
        # 테스트 실행
        session = boto3.Session()
        s3_client = session.client('s3')
        
        # 버킷 목록 테스트
        buckets = s3_client.list_buckets()
        self.assertEqual(len(buckets['Buckets']), 2)
        self.assertEqual(buckets['Buckets'][0]['Name'], 'test-bucket-1')
        
        # 버킷 ACL 테스트
        acl = s3_client.get_bucket_acl(Bucket='test-bucket-1')
        self.assertIn('Grants', acl)
    
    @patch('boto3.Session')
    def test_cloudtrail_service_connection(self, mock_session):
        """CloudTrail 서비스 연결 테스트"""
        # Mock 설정
        mock_cloudtrail_client = Mock()
        mock_cloudtrail_client.describe_trails.return_value = {
            'trailList': [
                {
                    'Name': 'test-trail',
                    'S3BucketName': 'cloudtrail-logs-bucket',
                    'IsLogging': True,
                    'IsMultiRegionTrail': True,
                    'IncludeGlobalServiceEvents': True
                }
            ]
        }
        mock_cloudtrail_client.get_trail_status.return_value = {
            'IsLogging': True,
            'LatestDeliveryTime': datetime.now(),
            'StartLoggingTime': datetime.now()
        }
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_cloudtrail_client
        mock_session.return_value = mock_session_instance
        
        # 테스트 실행
        session = boto3.Session()
        cloudtrail_client = session.client('cloudtrail')
        
        # Trail 목록 테스트
        trails = cloudtrail_client.describe_trails()
        self.assertEqual(len(trails['trailList']), 1)
        self.assertEqual(trails['trailList'][0]['Name'], 'test-trail')
        self.assertTrue(trails['trailList'][0]['IsLogging'])
        
        # Trail 상태 테스트
        status = cloudtrail_client.get_trail_status(Name='test-trail')
        self.assertTrue(status['IsLogging'])
    
    @patch('boto3.Session')
    def test_guardduty_service_connection(self, mock_session):
        """GuardDuty 서비스 연결 테스트"""
        # Mock 설정
        mock_guardduty_client = Mock()
        mock_guardduty_client.list_detectors.return_value = {
            'DetectorIds': ['detector-id-1']
        }
        mock_guardduty_client.get_detector.return_value = {
            'Status': 'ENABLED',
            'ServiceRole': 'arn:aws:iam::123456789012:role/aws-guardduty-service-role',
            'FindingPublishingFrequency': 'FIFTEEN_MINUTES'
        }
        mock_guardduty_client.list_findings.return_value = {
            'FindingIds': ['finding-1', 'finding-2']
        }
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_guardduty_client
        mock_session.return_value = mock_session_instance
        
        # 테스트 실행
        session = boto3.Session()
        guardduty_client = session.client('guardduty')
        
        # Detector 목록 테스트
        detectors = guardduty_client.list_detectors()
        self.assertEqual(len(detectors['DetectorIds']), 1)
        
        # Detector 상태 테스트
        detector = guardduty_client.get_detector(DetectorId='detector-id-1')
        self.assertEqual(detector['Status'], 'ENABLED')
        
        # Findings 목록 테스트
        findings = guardduty_client.list_findings(DetectorId='detector-id-1')
        self.assertEqual(len(findings['FindingIds']), 2)
    
    @patch('boto3.Session')
    def test_waf_service_connection(self, mock_session):
        """WAF 서비스 연결 테스트"""
        # Mock 설정
        mock_waf_client = Mock()
        mock_waf_client.list_web_acls.return_value = {
            'WebACLs': [
                {
                    'Name': 'test-web-acl',
                    'Id': 'web-acl-id-1',
                    'ARN': 'arn:aws:wafv2:ap-northeast-2:123456789012:regional/webacl/test-web-acl/web-acl-id-1'
                }
            ]
        }
        mock_waf_client.get_web_acl.return_value = {
            'WebACL': {
                'Name': 'test-web-acl',
                'Id': 'web-acl-id-1',
                'DefaultAction': {'Allow': {}},
                'Rules': [
                    {
                        'Name': 'test-rule',
                        'Priority': 1,
                        'Action': {'Block': {}}
                    }
                ]
            }
        }
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_waf_client
        mock_session.return_value = mock_session_instance
        
        # 테스트 실행
        session = boto3.Session()
        waf_client = session.client('wafv2')
        
        # Web ACL 목록 테스트
        web_acls = waf_client.list_web_acls(Scope='REGIONAL')
        self.assertEqual(len(web_acls['WebACLs']), 1)
        self.assertEqual(web_acls['WebACLs'][0]['Name'], 'test-web-acl')
        
        # Web ACL 상세 정보 테스트
        web_acl = waf_client.get_web_acl(
            Name='test-web-acl',
            Id='web-acl-id-1',
            Scope='REGIONAL'
        )
        self.assertEqual(web_acl['WebACL']['Name'], 'test-web-acl')
        self.assertEqual(len(web_acl['WebACL']['Rules']), 1)


class TestConnectionErrorHandling(unittest.TestCase):
    """연결 오류 처리 테스트"""
    
    @patch('boto3.Session')
    def test_no_credentials_error(self, mock_session):
        """자격 증명 없음 오류 테스트"""
        mock_session.side_effect = NoCredentialsError()
        
        with self.assertRaises(NoCredentialsError):
            session = boto3.Session()
    
    @patch('boto3.Session')
    def test_invalid_credentials_error(self, mock_session):
        """잘못된 자격 증명 오류 테스트"""
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.side_effect = ClientError(
            error_response={'Error': {'Code': 'SignatureDoesNotMatch', 'Message': 'Invalid signature'}},
            operation_name='GetCallerIdentity'
        )
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_sts_client
        mock_session.return_value = mock_session_instance
        
        session = boto3.Session()
        sts_client = session.client('sts')
        
        with self.assertRaises(ClientError) as context:
            sts_client.get_caller_identity()
        
        self.assertEqual(context.exception.response['Error']['Code'], 'SignatureDoesNotMatch')
    
    @patch('boto3.Session')
    def test_access_denied_error(self, mock_session):
        """접근 거부 오류 테스트"""
        mock_iam_client = Mock()
        mock_iam_client.get_account_summary.side_effect = ClientError(
            error_response={'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            operation_name='GetAccountSummary'
        )
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_iam_client
        mock_session.return_value = mock_session_instance
        
        session = boto3.Session()
        iam_client = session.client('iam')
        
        with self.assertRaises(ClientError) as context:
            iam_client.get_account_summary()
        
        self.assertEqual(context.exception.response['Error']['Code'], 'AccessDenied')
    
    @patch('boto3.Session')
    def test_service_unavailable_error(self, mock_session):
        """서비스 사용 불가 오류 테스트"""
        mock_s3_client = Mock()
        mock_s3_client.list_buckets.side_effect = ClientError(
            error_response={'Error': {'Code': 'ServiceUnavailable', 'Message': 'Service temporarily unavailable'}},
            operation_name='ListBuckets'
        )
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_s3_client
        mock_session.return_value = mock_session_instance
        
        session = boto3.Session()
        s3_client = session.client('s3')
        
        with self.assertRaises(ClientError) as context:
            s3_client.list_buckets()
        
        self.assertEqual(context.exception.response['Error']['Code'], 'ServiceUnavailable')


if __name__ == '__main__':
    # 테스트 실행
    print("AWS 연결 테스트 시작...")
    print("주의: 실제 AWS 연결 테스트는 환경 변수에 자격 증명이 설정된 경우에만 실행됩니다.")
    print("환경 변수: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION")
    print("-" * 60)
    
    unittest.main(verbosity=2)