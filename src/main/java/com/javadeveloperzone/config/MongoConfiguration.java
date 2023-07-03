package com.javadeveloperzone.config;

import org.bson.BsonReader;
import org.bson.BsonWriter;
import org.bson.codecs.Codec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.mongodb.core.convert.MongoCustomConversions;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Configuration
@EnableMongoRepositories("com.javadeveloperzone")
public class MongoConfiguration {

  @Value("${spring.data.mongodb.uri}")
  String mongoUri;

  @Value("${spring.data.mongodb.database}")
  String mongoDefaultDb;

  @Bean
  public MongoCustomConversions customConversions() {
    List<Converter<?, ?>> converters = new ArrayList<>();
    converters.add(new DateToZonedDateTimeConverter());
    converters.add(new ZonedDateTimeToDateConverter());
    return new MongoCustomConversions(converters);
  }

  class ZonedDateTimeCodec implements Codec<ZonedDateTime> {

    @Override
    public Class<ZonedDateTime> getEncoderClass() {
      return ZonedDateTime.class;
    }

    @Override
    public void encode(BsonWriter writer, ZonedDateTime value, EncoderContext encoderContext) {
      writer.writeDateTime(value.toInstant().toEpochMilli());
    }

    @Override
    public ZonedDateTime decode(BsonReader reader, DecoderContext decoderContext) {
      return ZonedDateTime
          .ofInstant(Instant.ofEpochMilli(reader.readDateTime()), ZoneId.systemDefault());
    }
  }

  class DateToZonedDateTimeConverter implements
      Converter<Date, ZonedDateTime> {

    @Override
    public ZonedDateTime convert(Date source) {
      return source == null ? null :
          ZonedDateTime.ofInstant(source.toInstant(), ZoneId.systemDefault());
    }
  }

  class ZonedDateTimeToDateConverter implements Converter<ZonedDateTime, Date> {

    @Override
    public Date convert(ZonedDateTime source) {
      return source == null ? null : Date.from(source.toInstant());
    }
  }
}
