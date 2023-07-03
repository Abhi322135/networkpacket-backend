package com.javadeveloperzone;

import org.springframework.boot.SpringApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@org.springframework.boot.autoconfigure.SpringBootApplication
@EnableAsync
public class SpringBootApplication {
    public static void main(String[] args) {

        SpringApplication.run(SpringBootApplication.class);
    }
    @Bean("AsyncExecution")
    public TaskExecutor getAsyncExecutor()
    {
        ThreadPoolTaskExecutor threadPoolExecutor=new ThreadPoolTaskExecutor();
        threadPoolExecutor.setThreadNamePrefix("Abhi");
        Thread.currentThread().resume();
        return threadPoolExecutor;
    }
}

