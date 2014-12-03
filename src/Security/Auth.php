<?php

namespace Guldenplaza\Auth\Security;

use \Phalcon\Validation\Validator\Confirmation;
use \Phalcon\Validation\Validator\Email;
use \Phalcon\Validation\Validator\PresenceOf;
use \Phalcon\Validation\Validator\StringLength;

/**
 * Auth
 *
 * This class is responsible for handling authorization
 */
class Auth extends \Phalcon\Mvc\User\Component {

	/**
	 * The configuration
	 */
	protected $_config;

	/**
	 * The logged in user
	 */
	protected $_user;

	/**
	 * The classname to use for the user
	 */
	protected $_className;

	/**
	 * Constructs a new auth object
	 */
	public function __construct(\Phalcon\Config $config, $classname = "Models\Users")
	{
		// Set the config
		$this->_config    = $config;
		$this->_className = $classname;
	}

	/**
	 * Get the currently logged in user
	 *
	 * @return  The currently logged in user or FALSE if there is not any
	 */
	public function getUser()
	{
		if($this->_user !== NULL)
			return $this->_user;

		if($this->session->has($this->_config->session_key))
		{
			$classname   = $this->_className;
			$this->_user = $classname::findFirst($this->session->get($this->_config->session_key));
		}
		else
		{
			$this->_user = FALSE;
		}

		return $this->_user;
	}

	/**
	 * Hashes a string with the hash key and hash method set in the configuration
	 *
	 * @return  The hashed string
	 */
	public function hash($string)
	{
		$hash_key    = $this->_config->hash_key;
		$hash_method = $this->_config->hash_method;

		return hash_hmac($hash_method, $string, $hash_key);
	}

	/**
	 * Logout the current user
	 */
	public function logout()
	{
		// Remove the session identifier
		$this->session->remove($this->_config->session_key);

		// Unset the user
		$this->_user = NULL;
	}

	/**
	 * Try to log the user in
	 *
	 * @param  username  The username
	 * @param  password  The password
	 * @param  remember  Whether to remember the user or not
	 *
	 * @return  TRUE on success FALSE on failure
	 */
	public function login($username, $password, $remember = FALSE)
	{
		$classname   = $this->_className;
		$this->_user = $classname::findFirst(array(
			'username = :username: AND password = :password:',
			'bind' => array(
				'username' => $username,
				'password' => $this->hash($password),
			)));

		if ($this->_user !== FALSE)
		{
			$this->session->set($this->_config->session_key, $this->_user->id);

			return TRUE;
		}

		return FALSE;
	}

	/**
	 * Check if a user is logged in
	 */
	public function loggedIn()
	{
		return ($this->getUser() !== FALSE);
	}

	/**
	 * Register a new user using given values
	 *
	 * @param  array  Values
	 *
	 * @return  Array of error messages
	 */
	public function registerUser(array $values)
	{
		$validation = new \Phalcon\Validation();

		$validation->add('username', new PresenceOf());

		$validation->add('email',    new PresenceOf());
		$validation->add('email',    new Email());

		$validation->add('password', new StringLength(array('min' => 8)));
		$validation->add('password', new PresenceOf());

		$validation->add('password_confirm', new PresenceOf());
		$validation->add('password_confirm', new Confirmation(array(
			'message' => 'The passwords are not the same',
			'with'    => 'password',
		)));

		$messages = $validation->validate($values);

		if (count($messages) !== 0)
			return $messages;

		$user           = new $this->_className();
		$user->username = $values['username'];
		$user->password = $this->hash($values['password']);
		$user->email    = $values['email'];
		$user->save();

		return $user->getMessages();
	}

	/**
	 * Set the class name to use for the user
	 *
	 * @throws  \Phalcon\Exception  when given class name is not found
	 *
	 * @param   String  Classname
	 */
	public function setClassName($classname)
	{
		if( ! class_exists($classname))
			throw new \Phalcon\Exception('Class '.$classname .' does not exist');
		else
			$this->_className = $classname;
	}

}
