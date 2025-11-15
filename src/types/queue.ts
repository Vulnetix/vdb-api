/**
 * Queue message types
 */
export interface QueueMessage {
    type: string
    payload: any
    timestamp: number
}

export interface MessageBatch<T = QueueMessage> {
    queue: string
    messages: Array<{
        id: string
        timestamp: Date
        body: T
    }>
}
