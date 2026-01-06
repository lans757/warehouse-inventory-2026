<?php
require_once('BaseModel.php');

class User extends BaseModel {
    protected $table = 'users';

    public function authenticate($username, $password) {
        $sql  = "SELECT id,username,password,user_level FROM {$this->table} WHERE username = ? LIMIT 1";
        $stmt = $this->db->query_prepared($sql, [$username]);
        if($this->db->num_rows($stmt)){
            $user = $this->db->fetch_assoc($stmt);
            if(password_verify($password, $user['password']) || sha1($password) === $user['password'] ){
                return $user;
            }
        }
        return false;
    }

    public function create($name, $username, $password, $level) {
        $name = remove_junk($name);
        $username = remove_junk($username);
        $password = password_hash($password, PASSWORD_DEFAULT);
        $level = (int)$level;
        $sql = "INSERT INTO {$this->table} (name, username, password, user_level, status) VALUES (?, ?, ?, ?, '1')";
        return $this->db->query_prepared($sql, [$name, $username, $password, $level]);
    }

    public function update($id, $name, $username, $level) {
        $name = remove_junk($name);
        $username = remove_junk($username);
        $level = (int)$level;
        $id = (int)$id;
        $sql = "UPDATE {$this->table} SET name = ?, username = ?, user_level = ? WHERE id = ?";
        return $this->db->query_prepared($sql, [$name, $username, $level, $id]);
    }

    public function updatePassword($id, $password) {
        $password = password_hash($password, PASSWORD_DEFAULT);
        $id = (int)$id;
        $sql = "UPDATE {$this->table} SET password = ? WHERE id = ?";
        return $this->db->query_prepared($sql, [$password, $id]);
    }

    public function updateImage($id, $image) {
        $id = (int)$id;
        $sql = "UPDATE {$this->table} SET image = ? WHERE id = ?";
        return $this->db->query_prepared($sql, [$image, $id]);
    }
}
