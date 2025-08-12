import { createClient, ClickHouseClient } from '@clickhouse/client';

class ClickHouseDB {
  private client: ClickHouseClient;
  private isConnected: boolean = false;

  constructor() {
    // ClickHouse client configuration for local desktop server
    const config = {
      url: process.env.CLICKHOUSE_URL || 'http://127.0.0.1:8123',
      username: process.env.CLICKHOUSE_USER || 'default',
      password: process.env.CLICKHOUSE_PASSWORD || '',
      database: process.env.CLICKHOUSE_DATABASE || 'l1_anomaly_detection',
    };
    
    console.log('🔗 Connecting to ClickHouse server at:', config.url);
    this.client = createClient(config);
  }

  async testConnection(): Promise<boolean> {
    try {
      const result = await this.client.query({
        query: 'SELECT 1 as test',
      });
      console.log('✅ ClickHouse connection successful');
      this.isConnected = true;
      return true;
    } catch (error) {
      console.error('❌ ClickHouse connection failed:', error.message);
      console.error('Please ensure ClickHouse is running on your local desktop server');
      this.isConnected = false;
      throw error;
    }
  }

  async queryWithParams(sql: string, queryParams: Record<string, any>): Promise<any> {
    try {
      const result = await this.client.query({
        query: sql,
        query_params: queryParams,
      });
      
      const data = await result.json();
      return data.data || [];
    } catch (error) {
      console.error('ClickHouse Query Error:', error);
      throw error;
    }
  }

  async query(sql: string, params: any[] = []): Promise<any> {
    if (!this.isConnected && !(await this.testConnection())) {
      throw new Error('ClickHouse not available');
    }
    
    try {
      // Use parameterized queries properly for ClickHouse
      const result = await this.client.query({
        query: sql,
        query_params: params.reduce((acc, param, index) => {
          acc[`param_${index}`] = param;
          return acc;
        }, {} as Record<string, any>),
      });
      
      const data = await result.json();
      return data.data || [];
    } catch (error) {
      console.error('ClickHouse Query Error:', error);
      
      // If parameterized query fails, try with substitution as fallback
      try {
        let processedQuery = sql;
        if (params && params.length > 0) {
          let paramIndex = 0;
          processedQuery = sql.replace(/\?/g, () => {
            const value = params[paramIndex++];
            if (value === null || value === undefined) return 'NULL';
            return typeof value === 'string' ? `'${value.replace(/'/g, "''")}'` : String(value);
          });
        }
        
        const result = await this.client.query({
          query: processedQuery,
        });
        
        const data = await result.json();
        return data.data || [];
      } catch (fallbackError) {
        console.error('ClickHouse Fallback Query Error:', fallbackError);
        throw fallbackError;
      }
    }
  }

  async insert(table: string, data: any[]): Promise<void> {
    if (!this.isConnected && !(await this.testConnection())) {
      throw new Error('ClickHouse not available');
    }

    try {
      await this.client.insert({
        table,
        values: data,
        format: 'JSONEachRow',
      });
    } catch (error) {
      console.error('ClickHouse Insert Error:', error);
      throw error;
    }
  }

  async command(sql: string): Promise<void> {
    if (!this.isConnected && !(await this.testConnection())) {
      throw new Error('ClickHouse not available');
    }

    try {
      await this.client.command({ query: sql });
    } catch (error) {
      console.error('ClickHouse Command Error:', error);
      throw error;
    }
  }

  getClient(): ClickHouseClient {
    return this.client;
  }

  isAvailable(): boolean {
    return this.isConnected;
  }
}

export const clickhouse = new ClickHouseDB();
export default clickhouse;