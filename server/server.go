package server

func Init(Port string) {
	r := NewRouter()
	r.Run(":" + Port)
}
