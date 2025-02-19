from unittest.mock import mock_open, patch

import pytest

from src.utils import SaveLoadManager


@patch("builtins.open", mock_open(read_data='{"key": "value"}'))
def test_load_config():
    """
    Test for the load_config method of SaveLoadManager
    """

    config = SaveLoadManager.load_config("test_path")

    expected_config = {"key": "value"}
    assert config == expected_config

    open.assert_called_once_with("test_path", "r")


def test_load_config_file_not_found():
    """
    FileNotFoundError to be raised
    When configuration file is not found
    """
    with patch("builtins.open", side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError):
            SaveLoadManager.load_config("wrong_cong_file.conf")
