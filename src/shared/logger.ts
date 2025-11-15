/**
 * Simple logger implementation
 */
export class Logger {
    private name: string
    private logLevel: string
    private levels: Record<string, number> = {
        'TRACE': 10, 'DEBUG': 20, 'INFO': 30, 'WARN': 40, 'ERROR': 50
    }

    constructor(name: string, logLevel: string = 'INFO') {
        this.name = name
        this.logLevel = logLevel
    }

    private shouldLog(level: string): boolean {
        return (this.levels[level] || 30) >= (this.levels[this.logLevel] || 30)
    }

    private log(level: string, message: string, data?: any) {
        if (!this.shouldLog(level)) return

        const timestamp = new Date().toISOString()
        const logData = data ? ` ${JSON.stringify(data)}` : ''
        console.log(`[${timestamp}] [${level}] [${this.name}] ${message}${logData}`)
    }

    trace(message: string, data?: any) {
        this.log('TRACE', message, data)
    }

    debug(message: string, data?: any) {
        this.log('DEBUG', message, data)
    }

    info(message: string, data?: any) {
        this.log('INFO', message, data)
    }

    warn(message: string, data?: any) {
        this.log('WARN', message, data)
    }

    error(message: string, data?: any) {
        this.log('ERROR', message, data)
    }
}
