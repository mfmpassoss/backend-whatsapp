import pkg from "pg"

const { Pool } = pkg

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'escola',
  password: '291294',
  port: 5432
})

export default pool