# Typed Secure Storage

Typed Secure Storage is a utility for secure, encrypted storage in the browser with type definition schema. It is built on top of the Web Crypto API and Local Storage. It is designed to be simple to use and easy to integrate into existing projects.

<img src="https://github.com/bxxf/typed-secure-storage/assets/43238984/eeec9a27-74e8-4534-b066-e7f035ea08d4" width="50%">


## Features

- **Type Definition Schema**: Easily define the schema of the data you want to store and retrieve.
- **Encryption**: Data is encrypted using the Web Crypto API using AES-GCM.

## Installation

```bash
bun install typed-secure-storage
```

## Usage

Here's how to quickly get started with `typed-secure-storage`:

1. **Define the schema**

```typescript
interface Todo {
  title: string;
  completed: boolean;
}

interface Schema {
  todos: Todo;
}
```

2. **Create a new instance of `TypedSecureStorage`**

```typescript
import { createTypedSecureStorage } from "typed-secure-storage";

const secretKey = "your-secret-key"; // Replace with your secret key
const salt = "your-salt"; // Replace with your salt

const storage = await createEncryptedStorage<Schema>(secretKey, salt);
```

3. **Use the storage**

```typescript
const todo: Todo = {
  title: "Buy milk",
  completed: false,
};

// Save a single item
const res = await storage.set("todos", todo);
// Get a single item
const todo = await storage.get("todos", res.key);
console.log(todo.title); // "Buy milk"
// Get all items
storage.getAll("todos");
// Filter items
storage.filter("todos", (todo) => todo.completed);
// Remove a single item
storage.remove("todos", res.key);
```

## Disclaimer

This project does not guarantee safety and security - all security-sensitive data and operations should not be handled in the client-side. This project is not responsible for any security breaches or data loss.
