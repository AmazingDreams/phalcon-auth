<?php

class TestUser extends \Phalcon\Mvc\Model {

	public $id;

	public function initialize()
	{
		$this->setSource('users');
	}

}
