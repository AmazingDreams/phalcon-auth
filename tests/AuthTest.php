<?php

require __DIR__.'/../vendor/autoload.php';
require __DIR__.'/Utils/TestDatabase.php';
require __DIR__.'/Utils/TestUser.php';
require __DIR__.'/Utils/TestSession.php';

use \Models\Users;

class AuthTest extends \PHPUnit_Framework_Testcase {

	protected $di;

	public function setUp()
	{
		$this->di = new \Phalcon\DI\FactoryDefault();
		$this->di->setShared('db', function() {
			$db = new TestDatabase();
			$db->cleanUp();
			$db->constructUsers();

			return $db;
		});
		$this->di->setShared('session', function() {
			$adapter = new TestSession;
			$adapter->start();

			return $adapter;
		});
		$this->di->set('auth', new \AD\Auth\Security\Auth(new \Phalcon\Config(array(
			'session_key' => 'testkey',
			'hash_key'    => 'hashkey',
			'hash_method' => 'sha256',
		)), '\TestUser'));

		\Phalcon\DI::setDefault($this->di);
	}

	public function testRegistration()
	{
		$auth = $this->di->get('auth');

		/* Test successful registration */
		$result = $auth->registerUser(array(
			'username'         => 'test_1',
			'email'            => 'test@example.com',
			'password'         => 'test_test_test',
			'password_confirm' => 'test_test_test',
		));

		$this->assertEquals(count($result), 0, 'Failures when registering user');

		$user = TestUser::findFirst(array(
			'username = :username:',
			'bind' => array('username' => 'test_1'),
		));

		$this->assertNotEquals($user, FALSE, 'Registered user not found in database');
		/* End test */

		/* Test invalid email registration */
		$result = $auth->registerUser(array(
			'username'         => 'test_2',
			'email'            => 'test',
			'password'         => 'test_test_test',
			'password_confirm' => 'test_test_test',
		));

		$this->assertNotEquals(count($result), 0, 'No failures when registering user, failures expected');

		$user = TestUser::findFirst(array(
			'username = :username:',
			'bind' => array('username' => 'test_2'),
		));

		$this->assertEquals($user, FALSE, 'User found in database that should have failed');
		/* End test */

		/* Test different password registration */
		$result = $auth->registerUser(array(
			'username'         => 'test_3',
			'email'            => 'test@example.com',
			'password'         => 'some_pass',
			'password_confirm' => 'some_other_pass',
		));

		$this->assertNotEquals(count($result), 0, 'No failures when registering user, failures expected');

		$user = TestUser::findFirst(array(
			'username = :username:',
			'bind' => array('username' => 'test_3'),
		));

		$this->assertEquals($user, FALSE, 'User found in database that should have failed');
		/* End test */

		/* Test invalid password registration */
		$result = $auth->registerUser(array(
			'username'         => 'test_4',
			'email'            => 'test@example.com',
			'password'         => 'short',
			'password_confirm' => 'short',
		));

		$this->assertNotEquals(count($result), 0, 'No failures when registering user, failures expected');

		$user = TestUser::findFirst(array(
			'username = :username:',
			'bind' => array('username' => 'test_4'),
		));

		$this->assertEquals($user, FALSE, 'User found in database that should have failed');
		/* End test */

		/* Test register empty user */
		$result = $auth->registerUser(array(
			'username'         => '',
			'email'            => '',
			'password'         => '',
			'password_confirm' => '',
		));

		$this->assertNotEquals(count($result), 0, 'No failures when registering, failures expected');

		$user = TestUser::findFirst(array(
			'username = :username:',
			'bind' => array('username' => ''),
		));

		$this->assertEquals($user, FALSE, 'User found in database that should have failed');
		/* End test */
	}

	public function testLoginSuccessPasswordV1()
	{
		$db = $this->di->get('db');

		// Insert user
		$result = $db->query('INSERT INTO `users` (`username`, `email`, `password`, `password_version`) VALUES(:username, :email, :password, :password_version)', array(
			'username'         => 'existing_user',
			'email'            => 'someemail@example.com',
			'password'         => '80ed70cf6ba151f600527b2949b0516d1ce04c1b5c5d3baa1b3cdd396fcbf16a',
			'password_version' => '1',
		));

		$success = $this->di->get('auth')->login('existing_user', 'some-password');

		$this->assertTrue($success);

		$user = $this->di->get('auth')->getUser();
		$this->assertNotNull($user);
		$this->assertEquals('existing_user', $user->username);
		$this->assertEquals(2, $user->password_version);
		$this->assertNotEquals('80ed70cf6ba151f600527b2949b0516d1ce04c1b5c5d3baa1b3cdd396fcbf16a', $user->password);
	}

	public function testLoginFailure()
	{
		$db = $this->di->get('db');

		$failed = $this->di->get('auth')->login('non_existing_user', 'non_existing_password');

		$this->assertFalse($failed);
	}

	public function testLoginEmailPasswordV1()
	{
		$db = $this->di->get('db');

		// Insert user
		$result = $db->query('INSERT INTO `users` (`username`, `email`, `password`, `password_version`) VALUES(:username, :email, :password, :password_version)', array(
			'username' => 'existing_user',
			'email'    => 'someemail@example.com',
			'password' => '80ed70cf6ba151f600527b2949b0516d1ce04c1b5c5d3baa1b3cdd396fcbf16a',
			'password_version' => 1,
		));

		$success = $this->di->get('auth')->login('someemail@example.com', 'some-password');

		$this->assertTrue($success);
	}

	public function testMixedCredentialsLogin()
	{
		$db   = $this->di->get('db');
		$auth = $this->di->get('auth');

		$auth->registerUser(array(
			'username'         => 'test_1',
			'email'            => 'test@example.com',
			'password'         => 'test_test_1',
			'password_confirm' => 'test_test_1',
		));
		$auth->registerUser(array(
			'username'         => 'test_2',
			'email'            => 'test2@example.com',
			'password'         => 'test_test_2',
			'password_confirm' => 'test_test_2',
		));

		// Check if both can login regularly
		$this->assertTrue($auth->login('test_1', 'test_test_1'));
		$this->assertTrue($auth->login('test_2', 'test_test_2'));

		// Login with email of 2 password of 1
		$this->assertFalse(
			$auth->login('test2@example.com', 'test_test_1')
		);

		// Login with username of 2 password of 1
		$this->assertFalse(
			$auth->login('test_2', 'test_test_1')
		);
	}

}
