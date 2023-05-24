import Packet from "@/lib/dns/Packet";
import { decodePacketFlags, OpCode, PacketType, RCode } from "@/lib/dns/PacketFlags";
import { decodeQuestions, QClass, QType, Question } from "@/lib/dns/Question";
import { encodeName, encodeUInt16BE } from "@/lib/dns/utils";
import { testProp, fc } from "@fast-check/jest";

// For all integers in set of values in QType/QClass
const fc_qtypes = fc.constantFrom(...Object.keys(QType).filter(key => isNaN(Number(key))).map(c => QType[c]));
const fc_qclasses = fc.constantFrom(...Object.keys(QClass).filter(key => isNaN(Number(key))).map(c => QClass[c]));

const fc_question = fc.record({
  name: fc.domain(),
  type: fc_qtypes,
  class: fc_qclasses
});

describe('Question', () => {
  testProp(
    "Decode - Single String Name",
    [fc_question],
    (originalQuestion) => {

      const rawQuestion = new Uint8Array([
        ...encodeName(originalQuestion.name),
        ...encodeUInt16BE(originalQuestion.type),
        ...encodeUInt16BE(originalQuestion.class)
      ]);

      const decodedQuestion = decodeQuestions(rawQuestion, 0, 1);

      expect(decodedQuestion).toEqual({
        data: [originalQuestion],
        readBytes: rawQuestion.byteLength
      });
    }
  );

  testProp(
    "Decode - Multiple String Name",
    [fc.array(fc_question, { minLength: 2, maxLength: 10 })],
    (originalQuestions) => {

      const originalQuestionUint8Array = originalQuestions.flatMap(q => {
        return [
          ...encodeName(q.name),
          ...encodeUInt16BE(q.type),
          ...encodeUInt16BE(q.class)
        ];
      })

      const rawQuestion = new Uint8Array([
        ...originalQuestionUint8Array
      ]);

      const decodedQuestion = decodeQuestions(rawQuestion, 0, originalQuestions.length);

      expect(decodedQuestion).toEqual({
        data: originalQuestions,
        readBytes: rawQuestion.byteLength
      });
    }
  );

  testProp(
    "Decode - Pointer Name",
    [fc_question],
    (originalQuestion) => {
      // Universal Type and Class
      const typeAndClass = new Uint8Array([
        ...encodeUInt16BE(originalQuestion.type),
        ...encodeUInt16BE(originalQuestion.class)
      ]);

      // Question with fake name to see if the pointer will select the correct record
      const questionWithFakeName = new Uint8Array([
        ...encodeName("fake.local"),
        ...typeAndClass
      ]);

      // Uint8Array with a question and a pointer to that question
      const rawQuestion = new Uint8Array([
        ...questionWithFakeName,
        ...encodeName(originalQuestion.name),
        ...typeAndClass,

        // Pointer Question Starts with 0xC0
        0xC0, questionWithFakeName.byteLength,
        ...typeAndClass
      ]);

      const decodedQuestion = decodeQuestions(rawQuestion, 0, 3);

      expect(decodedQuestion.data[2].name).toEqual(originalQuestion.name);
      expect(decodedQuestion.readBytes).toEqual(rawQuestion.byteLength);
    }
  );
});
