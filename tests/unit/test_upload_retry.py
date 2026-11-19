#!/usr/bin/env python3
"""Quick test to verify upload_file retry logic."""
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from validate_aws_policies.ops.ops import upload_file


def test_upload_success():
    """Test successful upload on first attempt."""
    print("Test 1: Successful upload on first attempt...")
    
    with patch('validate_aws_policies.ops.ops.boto3.client') as mock_client:
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3
        mock_s3.upload_file.return_value = None
        
        result = upload_file(Path("test.txt"), "test-bucket", "test-key")
        
        assert result is True, "Should return True on success"
        assert mock_s3.upload_file.call_count == 1, "Should call upload_file once"
        print("✅ Test 1 passed")


def test_upload_retry_then_success():
    """Test retry logic with success on second attempt."""
    print("\nTest 2: Retry logic with success on second attempt...")
    
    with patch('validate_aws_policies.ops.ops.boto3.client') as mock_client:
        with patch('validate_aws_policies.ops.ops.time.sleep') as mock_sleep:
            mock_s3 = MagicMock()
            mock_client.return_value = mock_s3
            
            # Fail first, succeed second
            mock_s3.upload_file.side_effect = [
                ClientError({'Error': {'Code': 'ServiceUnavailable'}}, 'upload_file'),
                None
            ]
            
            result = upload_file(Path("test.txt"), "test-bucket", "test-key", max_retries=3)
            
            assert result is True, "Should return True after retry"
            assert mock_s3.upload_file.call_count == 2, "Should call upload_file twice"
            assert mock_sleep.call_count == 1, "Should sleep once between retries"
            mock_sleep.assert_called_with(1)  # 2^0 = 1 second
            print("✅ Test 2 passed")


def test_upload_all_retries_fail():
    """Test all retries fail."""
    print("\nTest 3: All retries fail...")
    
    with patch('validate_aws_policies.ops.ops.boto3.client') as mock_client:
        with patch('validate_aws_policies.ops.ops.time.sleep') as mock_sleep:
            mock_s3 = MagicMock()
            mock_client.return_value = mock_s3
            
            # Always fail
            mock_s3.upload_file.side_effect = ClientError(
                {'Error': {'Code': 'ServiceUnavailable'}}, 
                'upload_file'
            )
            
            result = upload_file(Path("test.txt"), "test-bucket", "test-key", max_retries=3)
            
            assert result is False, "Should return False after all retries fail"
            assert mock_s3.upload_file.call_count == 3, "Should call upload_file 3 times"
            assert mock_sleep.call_count == 2, "Should sleep twice (not after last attempt)"
            print("✅ Test 3 passed")


def test_exponential_backoff():
    """Test exponential backoff timing."""
    print("\nTest 4: Exponential backoff timing...")
    
    with patch('validate_aws_policies.ops.ops.boto3.client') as mock_client:
        with patch('validate_aws_policies.ops.ops.time.sleep') as mock_sleep:
            mock_s3 = MagicMock()
            mock_client.return_value = mock_s3
            
            # Always fail
            mock_s3.upload_file.side_effect = ClientError(
                {'Error': {'Code': 'ServiceUnavailable'}}, 
                'upload_file'
            )
            
            upload_file(Path("test.txt"), "test-bucket", "test-key", max_retries=4)
            
            # Check exponential backoff: 2^0=1, 2^1=2, 2^2=4
            expected_calls = [((1,),), ((2,),), ((4,),)]
            assert mock_sleep.call_args_list == expected_calls, \
                f"Expected {expected_calls}, got {mock_sleep.call_args_list}"
            print("✅ Test 4 passed")


if __name__ == "__main__":
    try:
        test_upload_success()
        test_upload_retry_then_success()
        test_upload_all_retries_fail()
        test_exponential_backoff()
        print("\n🎉 All tests passed!")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
