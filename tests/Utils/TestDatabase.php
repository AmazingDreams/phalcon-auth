<?php

class TestDatabase extends \Phalcon\Db\Adapter\Pdo\Sqlite {

	private $_created_tables = array();

	public function __construct(array $descriptor = NULL)
	{
		$db_file = '/tmp/amazingdreams-auth-unittest.db';

		if (file_exists($db_file))
		{
			unlink($db_file);
		}

		parent::__construct(array('dbname' => $db_file));
	}

	public function cleanUp()
	{
		// Drop tables
		foreach($this->_created_tables as $table)
		{
			$this->query("DROP TABLE `$table`");
		}

		// Reset cretaed tables
		$this->_created_tables = array();
	}

	public function constructUsers()
	{
		$this->query('CREATE TABLE `users` (
			`username`           VARCHAR(255)
			, `email`            VARCHAR(255)
			, `password`         VARCHAR(255)
			, `password_version` INTEGER
		)');

		$this->_created_tables[] = 'users';
	}

}
