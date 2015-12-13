<?php

namespace CustomAuth;

/**
 * SimpleAuth basic login driver
 *
 * @package     Fuel
 * @subpackage  Auth
 */
class Auth_Login_Simpleauth extends \Auth\Auth_Login_Simpleauth
{
	/**
	 * Check the user exists
	 *
	 * @return  bool
	 */
	public function validate_user($username = '', $password = '')
	{
		$username = trim($username) ?: trim(\Input::post(\Config::get('simpleauth.username_post_key', 'username')));
		$password = trim($password) ?: trim(\Input::post(\Config::get('simpleauth.password_post_key', 'password')));

		if (empty($username) or empty($password))
		{
			return false;
		}

		$password = $this->hash_password($password);
		$user = \DB::select_array(\Config::get('simpleauth.table_columns', array('*')))
			->where_open()
			->where('username', '=', $username)
			->where_close()
			->where('password', '=', $password)
			->from(\Config::get('simpleauth.table_name'))
			->execute(\Config::get('simpleauth.db_connection'))->current();

		return $user ?: false;
	}

	/**
	 * Login user
	 *
	 * @param   string
	 * @param   string
	 * @return  bool
	 */
	public function login($username = '', $password = '')
	{
		if ( ! ($this->user = $this->validate_user($username, $password)))
		{
			$this->user = \Config::get('simpleauth.guest_login', true) ? static::$guest_login : false;
			\Session::delete('username');
			\Session::delete('login_hash');
			return false;
		}

		// register so Auth::logout() can find us
		Auth::_register_verified($this);

		\Session::set('username', $this->user['username']);
		\Session::set('login_hash', $this->create_login_hash());
		\Session::instance()->rotate();
		return true;
	}


	/**
	 * Create new user
	 *
	 * @param   string
	 * @param   string
	 * @param   string
	 * @param   int    group id
	 * @param   Array
	 * @return  bool
	 */
	public function create_user($username, $password, $email = null, $group = 1, Array $profile_fields = array())
	{
		$password = trim($password);

		if(!empty($email))
		{
			$email = filter_var(trim($email), FILTER_VALIDATE_EMAIL);
			if(empty($email))
			{
				throw new \SimpleUserUpdateException('emailの形式が不正です。', 1);
			}
		}

		if (empty($username) or empty($password))
		{
			throw new \SimpleUserUpdateException('Username, password is not given', 1);
		}

		$same_users = \DB::select_array(\Config::get('simpleauth.table_columns', array('*')))
			->where('username', '=', $username)
			->from(\Config::get('simpleauth.table_name'))
			->execute(\Config::get('simpleauth.db_connection'));

		if ($same_users->count() > 0)
		{
			throw new \SimpleUserUpdateException('Username already exists', 3);
		}

		$user = array(
			'username'        => (string) $username,
			'password'        => $this->hash_password((string) $password),
			'email'           => $email,
			'group'           => (int) $group,
			'profile_fields'  => serialize($profile_fields),
			'last_login'      => 0,
			'login_hash'      => '',
			'created_at'      => \Date::forge()->get_timestamp(),
		);
		$result = \DB::insert(\Config::get('simpleauth.table_name'))
			->set($user)
			->execute(\Config::get('simpleauth.db_connection'));

		return ($result[1] > 0) ? $result[0] : false;
	}

	/**
	 * Update a user's properties
	 * Note: Username cannot be updated, to update password the old password must be passed as old_password
	 *
	 * @param   Array  properties to be updated including profile fields
	 * @param   string
	 * @return  bool
	 */
	public function update_user($values, $username = null)
	{
		$username = $username ?: $this->user['username'];
		$current_values = \DB::select_array(\Config::get('simpleauth.table_columns', array('*')))
			->where('username', '=', $username)
			->from(\Config::get('simpleauth.table_name'))
			->execute(\Config::get('simpleauth.db_connection'));

		if (empty($current_values))
		{
			throw new \SimpleUserUpdateException('Username not found', 4);
		}

		$update = array();
		if (array_key_exists('username', $values))
		{
			throw new \SimpleUserUpdateException('Username cannot be changed.', 5);
		}
		if (array_key_exists('password', $values))
		{
			if (empty($values['old_password'])
				or $current_values->get('password') != $this->hash_password(trim($values['old_password'])))
			{
				throw new \SimpleUserWrongPassword('Old password is invalid');
			}

			$password = trim(strval($values['password']));
			if ($password === '')
			{
				throw new \SimpleUserUpdateException('Password can\'t be empty.', 6);
			}
			$update['password'] = $this->hash_password($password);
			unset($values['password']);
		}
		if (array_key_exists('old_password', $values))
		{
			unset($values['old_password']);
		}
		if (array_key_exists('email', $values))
		{
			$email = filter_var(trim($values['email']), FILTER_VALIDATE_EMAIL);
			if ( ! $email)
			{
				throw new \SimpleUserUpdateException('Email address is not valid', 7);
			}
			$update['email'] = $email;
			unset($values['email']);
		}
		if (array_key_exists('group', $values))
		{
			if (is_numeric($values['group']))
			{
				$update['group'] = (int) $values['group'];
			}
			unset($values['group']);
		}
		if ( ! empty($values))
		{
			$profile_fields = @unserialize($current_values->get('profile_fields')) ?: array();
			foreach ($values as $key => $val)
			{
				if ($val === null)
				{
					unset($profile_fields[$key]);
				}
				else
				{
					$profile_fields[$key] = $val;
				}
			}
			$update['profile_fields'] = serialize($profile_fields);
		}

		$update['updated_at'] = \Date::forge()->get_timestamp();

		$affected_rows = \DB::update(\Config::get('simpleauth.table_name'))
			->set($update)
			->where('username', '=', $username)
			->execute(\Config::get('simpleauth.db_connection'));

		// Refresh user
		if ($this->user['username'] == $username)
		{
			$this->user = \DB::select_array(\Config::get('simpleauth.table_columns', array('*')))
				->where('username', '=', $username)
				->from(\Config::get('simpleauth.table_name'))
				->execute(\Config::get('simpleauth.db_connection'))->current();
		}

		return $affected_rows > 0;
	}
}

// end of file simpleauth.php