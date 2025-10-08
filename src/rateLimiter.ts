export class RateLimiter implements DurableObject {
	private state: DurableObjectState;

	constructor(state: DurableObjectState) {
		this.state = state;
	}

	async fetch(request: Request): Promise<Response> {
		const { key, limit, window } = await request.json<{
			key: string;
			limit: number;
			window: number;
		}>();

		const now = Date.now();
		const windowStart = now - window * 1000;

		// Get existing requests from storage
		const requests = (await this.state.storage.get<number[]>(key)) || [];

		// Filter out requests outside the current window
		const recentRequests = requests.filter((timestamp) => timestamp > windowStart);

		// Check if limit exceeded
		if (recentRequests.length >= limit) {
			return new Response(
				JSON.stringify({ success: false }),
				{ headers: { "Content-Type": "application/json" } }
			);
		}

		// Add current request
		recentRequests.push(now);

		// Store updated requests
		await this.state.storage.put(key, recentRequests);

		// Set alarm to clean up old data
		const alarmTime = now + window * 1000;
		await this.state.storage.setAlarm(alarmTime);

		return new Response(
			JSON.stringify({ success: true }),
			{ headers: { "Content-Type": "application/json" } }
		);
	}

	async alarm(): Promise<void> {
		// Clean up old entries
		const now = Date.now();
		const keys = await this.state.storage.list();

		for (const [key, timestamps] of keys.entries()) {
			if (Array.isArray(timestamps)) {
				const recent = timestamps.filter((ts: number) => ts > now - 60000);
				if (recent.length === 0) {
					await this.state.storage.delete(key);
				} else {
					await this.state.storage.put(key, recent);
				}
			}
		}
	}
}